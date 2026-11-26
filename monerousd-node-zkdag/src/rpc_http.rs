// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Live loopback HTTP RPC transport for the RUNNING node ([`crate::node_runtime::NodeRuntime`]).
//!
//! [`crate::rpc`] is the transport-independent request→effect core; THIS module is the wire that binds
//! it to a real socket so the greenfield wallet (and any local dApp) can actually reach the node. It is
//! the missing "transport increment" [`crate::rpc`] referred to: without it, the wallet POSTs
//! `/submit_pq_tx` into the void and every broadcast button fails with a connection error.
//!
//! It drives the LIVE [`NodeRuntime`], not a bare snapshot — so the node PROVES/VERIFIES/RELAYS
//! automatically: a tx submitted here goes through [`NodeRuntime::submit_tx`], which ingests it (the
//! mempool gate re-verifies via the light decider, so an invalid carrier is rejected) AND gossips it to
//! peers over the constant-rate onion cell channel; the runtime's tick loop in turn drains inbound peer
//! txs/blocks, consensus-verifies + grafts them, and re-gossips — so every node converges without any
//! manual relay. The wallet's OWN native contract (`core/pq-relay.cjs` + `core/pq-rpc.cjs`):
//!   * `POST /submit_pq_tx`  body `{"tx_as_hex":"<hex>","pow_stamp":<u64>,"do_not_relay":bool}`
//!       → hex-decode the carrier blob → [`NodeRuntime::submit_tx`] (verify + pool + gossip) →
//!         `{"status":"OK","tx_hash":"<hex>"}` on accept, `{"status":"REJECTED","reason":"<why>"}` on a
//!         fail-closed rejection (invalid carrier / insufficient anti-spam stamp / dup nullifier).
//!   * `GET  /get_info`   → live DAG/mempool/params snapshot.
//!   * `GET  /get_height` / `/get_tip` → the selected tip + its blue-score (the DAG's canonical height).
//!
//! Std-only (no HTTP/JSON crate): the bodies are tiny + fixed-shape, so a hand HTTP/1.1 reader + a
//! minimal JSON writer keep the node's dependency surface (and compile) small. Binds 127.0.0.1 ONLY
//! (loopback, Pillar-1: no metadata leaves the box); the P2P mesh ([`crate::net`]) is onion-only + separate.

use crate::fixed::FixedBytes;
use crate::mempool::PqTx;
use crate::node_runtime::NodeRuntime;
use crate::rpc::{RpcRequest, RpcResponse, RPC_DEFAULT_PORT, RPC_LOOPBACK_HOST};
use crate::transport::CellTransport;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// Bind a loopback [`TcpListener`] with `SO_REUSEADDR` so a RESTARTED node RECLAIMS its own port from a
/// `TIME_WAIT` socket a just-killed prior instance left behind. Plain `TcpListener::bind` omits `SO_REUSEADDR`,
/// so for ~30-60s (2·MSL) after a kill the port reads "busy" (bind → `EADDRINUSE`, invisible to `lsof`) — which
/// made [`pick_free_rpc_port`](crate) silently DRIFT the node to the next port, and since the port keys the
/// snapshot + onion identity, the restart silently resumed a DIFFERENT chain + published a DIFFERENT `.onion`
/// (a self-inflicted chain-identity fork). `SO_REUSEADDR` reclaims ONLY a stale socket: a genuinely LIVE
/// listener on the port STILL fails the bind (`SO_REUSEADDR` ≠ `SO_REUSEPORT`; it does not let two live
/// listeners share a port), so a real SECOND node still auto-selects a fresh port. Same host/port surface as
/// `TcpListener::bind` — the node's loopback-only, single-listener RPC. ([[feedback_no_broad_pkill_running_node]])
pub fn reusable_tcp_listener(host: &str, port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr: std::net::SocketAddr = format!("{host}:{port}").parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("bad rpc addr: {e}"),
        )
    })?;
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?; // reclaim a dead instance's TIME_WAIT socket; a LIVE listener still EADDRINUSEs
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

/// Start the SELF-MAINTAINING deposit watchers (idempotent): a background thread keeps every watched reserve
/// address's confirmed sats warm over the onion pool, so the deposit-status RPC + mint gate stay O(1) instant. The ONE
/// site every RPC server calls (the production [`serve`] and the simulator's listener), so a wallet sees the same coins
/// through either — the simulator once served an empty coin cache because only `serve` started them.
pub fn start_watchers() {
    crate::btc_watch::start_deposit_watch();
    crate::xmr_watch::start_deposit_watch();
}

/// Serve the loopback HTTP RPC on `127.0.0.1:port`, driving the shared running [`NodeRuntime`]. Blocks
/// forever (run it on its own thread). The runtime is shared (Arc<Mutex>) with the tick/relay loop so a
/// submitted tx is verified + pooled + gossiped against the SAME live DAG the producer builds on.
pub fn serve<T: CellTransport + Send + 'static>(
    rt: Arc<Mutex<NodeRuntime<T>>>,
    port: u16,
) -> std::io::Result<()> {
    start_watchers();
    // SO_REUSEADDR bind: a restart reclaims its own port from a stale TIME_WAIT socket instead of drifting to a
    // new port + snapshot + onion (the self-inflicted restart fork). See `reusable_tcp_listener`.
    let listener = reusable_tcp_listener(RPC_LOOPBACK_HOST, port)?;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let rt = Arc::clone(&rt);
                // One thread per connection: the wallet fires an infrequent large POST after a
                // multi-second prove; a blocked reader must not stall other local callers.
                std::thread::spawn(move || {
                    let _ = handle_conn(s, &rt);
                });
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

/// ⭐ DB-273 §19 L1 — THE ONE READ OF AN OWNER-NAMED DOOR'S OWNER: `note_clue_hex`, the credited (or change) note's OLI
/// clue (`oli::tag_clue_bytes_v2` for an index the wallet reserved). `None` for a missing, empty, malformed or oversized
/// clue — every peg door refuses a request without one (§17 condition 1: a note nobody can find is a burn wearing a
/// default). No bucket and no ML-KEM key is read on these doors any more.
fn owner_clue_field(body: &str) -> Option<Vec<u8>> {
    let clue = json_str_field(body, "note_clue_hex").and_then(|h| hex_decode(&h))?;
    (!clue.is_empty() && clue.len() <= crate::peg_in_tx::OWNER_CLUE_MAX).then_some(clue)
}

/// ⭐ DB-273 §19 — THE OWNERS OF AN OBJECT'S NOTES, IN THE OBJECT'S ORDER: the one clue-list codec's records
/// (`Node::parse_note_clue_records`, whole or not at all) from `note_clues_hex`, accepted only when there is exactly one
/// record per note and each names THAT note's commitment. A missing, extra, reordered or foreign record is `None`, never
/// a partial list — the object's decode then refuses the missing owners. One reader for every multi-note owner-named
/// door (yield, asset spend, the fill's taker slots), so the keying rule cannot drift between them.
fn clues_keyed_to_notes(body: &str, notes: &[&[u8]]) -> Option<Vec<Vec<u8>>> {
    let recs = json_str_field(body, "note_clues_hex")
        .and_then(|h| hex_decode(&h))
        .and_then(|b| crate::node::Node::parse_note_clue_records(&b))?;
    (recs.len() == notes.len() && recs.iter().zip(notes).all(|((cm, _), note)| note.get(..32) == Some(&cm[..])))
        .then(|| recs.into_iter().map(|(_, clue)| clue).collect())
}

/// Parse the flat attestor concat `pubkey_len(u16 LE) ‖ pubkey ‖ sig_len(u16 LE) ‖ sig` (repeated) that the
/// peg RPCs carry — the same wire shape as `/authorize_mint`. A truncated record ends the parse (fail-closed).
fn parse_peg_attestors(ab: &[u8]) -> Vec<crate::psm::MintAttestor> {
    let mut attestors = Vec::new();
    let mut off = 0;
    while off + 2 <= ab.len() {
        let plen = u16::from_le_bytes([ab[off], ab[off + 1]]) as usize;
        off += 2;
        if off + plen + 2 > ab.len() {
            break;
        }
        let pubkey = ab[off..off + plen].to_vec();
        off += plen;
        let slen = u16::from_le_bytes([ab[off], ab[off + 1]]) as usize;
        off += 2;
        if off + slen > ab.len() {
            break;
        }
        let sig = ab[off..off + slen].to_vec();
        off += slen;
        attestors.push(crate::psm::MintAttestor { pubkey, sig });
    }
    attestors
}

/// The peg outcome as a stable RPC string.
fn peg_outcome_str(o: &crate::peg::PegOutcome) -> &'static str {
    match o {
        crate::peg::PegOutcome::Minted(_) => "MINTED",
        crate::peg::PegOutcome::Redeemed(_) => "REDEEMED",
        crate::peg::PegOutcome::ConfidentialMinted => "CONFIDENTIAL_MINTED",
        crate::peg::PegOutcome::ConfidentialPublished => "CONFIDENTIAL_PUBLISHED",
        crate::peg::PegOutcome::ConfidentialRedeemed => "CONFIDENTIAL_REDEEMED",
        crate::peg::PegOutcome::Liquidated => "LIQUIDATED",
        crate::peg::PegOutcome::TheftRepaid => "THEFT_REPAID",
        crate::peg::PegOutcome::WrappedAssetRegistered => "WRAPPED_ASSET_REGISTERED",
        crate::peg::PegOutcome::PriceMarked(_) => "PRICE_MARKED",
        crate::peg::PegOutcome::InsufficientThreshold => "INSUFFICIENT_THRESHOLD",
        crate::peg::PegOutcome::Replay => "REPLAY",
        crate::peg::PegOutcome::BadRequest => "BAD_REQUEST",
        crate::peg::PegOutcome::Underbonded => "UNDERBONDED",
    }
}

/// ⭐ R7 — THE UI HARNESS'S NODE (layer 2): serve `rt`'s production RPC on `listener` through the daemon's own connection
/// handler ([`handle_conn`], every route and door unchanged), WITHOUT the deposit watchers [`serve`] starts (they reach the
/// onion network). The wallet's UI pins drive the SHIPPED front end against the real core and this in-process node, so a
/// flow asserts what the node (and its peer) hold. Returns when `stop` is set. Nothing in a node binary calls it.
pub fn serve_listener_for_harness<T: CellTransport + Send + 'static>(
    listener: TcpListener,
    rt: Arc<Mutex<NodeRuntime<T>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                let rt = Arc::clone(&rt);
                std::thread::spawn(move || {
                    let _ = handle_conn(s, &rt);
                });
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    }
}

pub(crate) fn handle_conn<T: CellTransport>(
    mut s: TcpStream,
    rt: &Arc<Mutex<NodeRuntime<T>>>,
) -> std::io::Result<()> {
    let (method, path, body, from) = match read_request(&mut s) {
        Some(r) => r,
        None => return write_response(&mut s, 400, "{\"status\":\"BAD_REQUEST\"}", None),
    };
    // ⛔ DB-374: only the user's own software reaches the node — never a web page the user happens to visit
    // (localhost CSRF, DNS rebinding). Refused before any route runs.
    let cors = match crate::local_origin::admit(&from, false) {
        Ok(c) => c,
        Err(why) => {
            return write_response(&mut s, 403, &format!("{{\"status\":\"FORBIDDEN\",\"error\":\"{why}\"}}"), None);
        }
    };
    let (code, json) = route(rt, &method, &path, &body);
    write_response(&mut s, code, &json, cors.as_deref())
}

/// Map a parsed request to a response rendered as JSON, against the LIVE running node. Kept pure over
/// `(method, path, body)` so it is unit-testable with no socket (crate-visible so a two-party pin in another
/// module — `db350_cm_ask_privacy_tests` — drives a wallet's exact requests through it).
pub(crate) fn route<T: CellTransport>(
    rt: &Arc<Mutex<NodeRuntime<T>>>,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    // ⛔ THE QUERY STRING IS REQUEST DATA, NOT NOISE. This used to `split('?')` and DISCARD it, so every
    // handler read its fields from the body alone and a GET carrying `?field=value` parsed NOTHING — each
    // handler then fell through to its own `unwrap_or` default and answered, under `"status":"OK"`, the
    // question it invented rather than the one asked. A well-formed WRONG answer is worse than an error
    // because the caller cannot tell it from a right one.
    //
    // Fold the query into the body when the body is empty, so every existing field reader works for GET
    // exactly as written. All-digit values stay unquoted so numeric readers see numbers; anything else is
    // quoted, with quotes and backslashes dropped so a crafted query cannot forge extra JSON fields, and
    // non-identifier keys are ignored. Pure request decoding — it reads no state and answers nothing itself.
    // Property and measurements:
    // `two_nodes_answer_a_membership_transition_query_identically_and_never_substitute_genesis`.
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };
    #[cfg(test)]
    crate::test_census::sim_coverage::note("route", &format!("{method} {path}")); // the simulator's coverage census
    let from_query;
    let body = if body.trim().is_empty() && !query.is_empty() {
        let mut fields: Vec<String> = Vec::new();
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            if !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) {
                fields.push(format!("\"{k}\":{v}"));
            } else {
                let esc: String = v.chars().filter(|c| *c != '"' && *c != '\\').collect();
                fields.push(format!("\"{k}\":\"{esc}\""));
            }
        }
        from_query = format!("{{{}}}", fields.join(","));
        from_query.as_str()
    } else {
        body
    };
    // ⭐ A-F114: the spender's absence wrappers for an object this call submits (`canon_chain::scope_spender_wrappers`),
    // for this call only; none before the upgrade
    let _spender_wrappers = crate::canon_chain::scope_spender_wrappers(
        json_str_field(body, "canon_absence_hex").filter(|_| crate::params::canon_live()).and_then(|h| hex_decode(&h)),
    );
    match (method, path) {
        // CORS preflight — a framed launchpad app (browser build) POSTs application/json here, which the browser
        // preflights. Answer OPTIONS 200 (write_response already carries the Access-Control-* headers).
        ("OPTIONS", _) => (200, "{\"status\":\"OK\"}".to_string()),
        // PRIVATE-CHAIN JSON-RPC shim — the real explorer SPA speaks Monero-style /json_rpc. Serve the methods it
        // needs WITHOUT any transparency surface: every block reports `num_txes` = the CONSTANT 256
        // (crate::cover::BLOCK_FIXED_TX_COUNT), IDENTICAL for every block — it is padded to a CONSTANT, so there is
        // nothing an observer can subtract to recover a real count (which of those 256 slots are real stays secret,
        // seeded in crate::cover, never here). get_transactions returns no tx (a private chain exposes no tx list);
        // get_info/get_block_count mirror the O(1) chain tip. The block `hash` is a deterministic per-height block
        // IDENTIFIER — a display label for the explorer row (the O(1) node retains no per-block history), NOT any
        // entropy function. DIGITAL-CASH-PRIVACY-REVIEWED: the only per-block number served is the fixed 256 constant;
        // nothing here reveals real tx count, value, sender, or ordering.
        // ⭐ THE HONEST LIVE-DAG SERVE — the RAM DAG's real recent structure (ids, parent edges, blue
        // scores, timestamps, selected-chain membership), the consensus-public facts gossip already
        // hands every peer.
        // ROOT-LAYER: this route is a pure PROJECTION of `Dag::dag_recent_view` — the Dag struct is
        // the sole producer of edges/scores/selected-chain; nothing is derived or invented here.
        // MEASURED: 2026-08-25 on-screen — the explorer's Live DAG scene drew 0 blocks (its feed was a
        // retired clearnet host + an unimplemented get_block_headers_range); with this serve + the
        // same-origin proxy the scene draws the node's real held blocks and real parent edges.
        // MUST-STAY-GREEN: the full rpc_http route table and node sweep — read-only route, no state.
        // Page width fixed at 96 newest blocks — a display page over the DAG's own O(1) retention.
        // Each row also carries the header's `work` (lane timewarp, 2026-11-15): the DAA target each block was mined at, a
        // consensus-public header field every peer already holds, so a real-node check can verify on the live chain that the
        // target never moves past `miner::DAA_CLAMP` per block and that stamps keep to median-time-past (the time-warp row).
        // A decimal string: a u128 does not fit a JSON number exactly. DIGITAL-CASH-PRIVACY-REVIEWED: work is the header's
        // public difficulty, the same for every block of a window; it names no transaction, value or person.
        ("GET", "/dag_recent") | ("POST", "/dag_recent") => {
            let view: Vec<_> = {
                let g = rt.lock().unwrap_or_else(|e| e.into_inner());
                let dag = g.node().dag();
                dag.dag_recent_view(96)
                    .into_iter()
                    .map(|(id, parents, blue, ts, sel)| {
                        let work = dag.get(&id).map_or(0, |n| n.header.work);
                        (id, parents, blue, ts, sel, work)
                    })
                    .collect()
            };
            let rows: Vec<String> = view
                .iter()
                .map(|(id, parents, blue, ts, sel, work)| {
                    let pj: Vec<String> = parents
                        .iter()
                        .map(|p| format!("\"{}\"", hex_encode(p.as_bytes())))
                        .collect();
                    format!(
                        "{{\"id\":\"{}\",\"parents\":[{}],\"blue_score\":{},\"ts\":{},\"selected\":{},\"work\":\"{}\"}}",
                        hex_encode(id.as_bytes()),
                        pj.join(","),
                        blue,
                        ts,
                        sel,
                        work
                    )
                })
                .collect();
            (
                200,
                format!("{{\"status\":\"OK\",\"blocks\":[{}]}}", rows.join(",")),
            )
        }
        ("GET", "/amm_pool") | ("POST", "/amm_pool") | ("POST", "/submit_amm") => {
            // ⛔ THE POOL AMM IS RETIRED (user ruling 2026-08-26): a pool is shared mutable secret
            // state, and every pillar failure of the DEX traced to that one property — so the DEX is
            // being rebuilt as pre-authorised ZK limit orders settled peer-to-peer (no pool, no
            // reserves, no openings). These routes answer with a tombstone instead of vanishing, so a
            // caller built against the pool surface learns WHY it is gone rather than guessing at a 404.
            (
                410,
                "{\"status\":\"GONE\",\"error\":\"the pool AMM is retired; the DEX is moving to peer-to-peer ZK limit orders — this surface will not return\"}"
                    .to_string(),
            )
        }
        // ── DEX ORDER-BOOK SETTLEMENT — the peer-to-peer successor to the retired pool. A taker submits
        //    the COMPOSED fill: the maker's resting half (carried verbatim from the book) plus their own
        //    taker half. The node admits it through `Node::execute_order_fill`, whose gates are the whole
        //    story: composed-proof verify, expiry, self-dealing refusal, owner-filed credits, and the
        //    existing double-spend gate as anti-double-fill. Fail-closed and atomic — a refusal mutates
        //    NOTHING, and every refusal names its gate.
        //
        //    ROOT-LAYER: this route is the PRODUCER of the fill submission surface — the settlement engine
        //    (`Node::execute_order_fill`) existed with ZERO call sites, so no taker anywhere could reach
        //    it; wiring belongs here, at the node's public RPC, not in any client that would fake it.
        //    MEASURED: finish-before-testing guard 2026-08-27 flagged `node.rs::execute_order_fill` as
        //    built-not-wired (0 call sites); after this route lands the engine is reachable end-to-end.
        //    MUST-STAY-GREEN: the retired-AMM tombstone (410 on /amm_pool + /submit_amm, gate STEP 8),
        //    the node lib suite, and the wallet crate's order-compose tests (6/6 incl. the
        //    cheaper-price non-compose refusal). ──
        // ── DEX ORDER BOOK — post a resting order, and read a level. The book is RAM/gossip only and
        //    never consensus state, so nothing here touches a root, an accumulator or a block id.
        ("POST", "/post_order") => {
            // hex(LE limbs) -> fixed-width limb array. A field of the WRONG LENGTH is refused, never
            // padded or truncated: a short asset tag padded with zeros is a DIFFERENT asset, and a short
            // nullifier is a different note.
            // ⭐ NOT §AG CLASS 9 (audited 2026-09-13): an asset tag is `[u64; 3]` by TYPE — the walk's
            // bound is that array's own length and the source is checked to be exactly 8 × it. Nothing
            // here is a digest or sized by `DIGEST_LANES`.
            fn limbs3(body: &str, field: &str) -> Option<[u64; 3]> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                if b.len() != 24 {
                    return None;
                }
                // NOT §AG CLASS 9: `[u64; 3]` by type, source checked to exactly 8 × 3 — no lane count.
                Some(core::array::from_fn(|i| {
                    u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0u8; 8]))
                }))
            }
            // A digest field (the maker's nullifier / leaf commit / payout cm — values the maker's PROVER
            // produced) arrives in the ONE canonical 32-byte digest form (`leaf_to_cm_bytes`, exactly as
            // `/book_level` serves it and as the settlement engine writes its tags) and is recovered by
            // the injective decode. ⛔ §AG CLASS 9 lived here: `from_fn` over `DIGEST_LANES` lanes read
            // `b[i*8..i*8+8]` off a 32-byte buffer and PANICKED the route at lane 4 (the `unwrap_or`
            // never ran — the slice index panics first). ⛔ §AI: NOT `cm_bytes_to_leaf` — a digest
            // round-tripped through the hash is not that digest, and the book keys on the prover's.
            // CHAIN-PUBLISH-REVIEWED: a wire-field parser (hex → digest), a read of the request; it moves
            // no value — the order it feeds is a resting OFFER, published by nothing until a fill.
            fn limbs4(body: &str, field: &str) -> Option<crate::spend_frontier::Digest4> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                let arr = <[u8; 32]>::try_from(b.as_slice()).ok()?;
                crate::spend_frontier::cm_bytes_to_root(&arr)
            }
            // Every field is REQUIRED. A missing one is a 400, never a defaulted limb — a zero tag or a
            // zero nullifier would be a different order than the maker proved.
            let parsed = (|| -> Option<crate::order_book::RestingOrder> {
                Some(crate::order_book::RestingOrder {
                    terms: usdm_decider::whir_rec_block::OrderTerms {
                        lot: json_num_field(body, "lot")?,
                        pay_b: json_num_field(body, "pay_b")?,
                        asset_a: limbs3(body, "asset_a")?,
                        asset_b: limbs3(body, "asset_b")?,
                        expires_at_height: json_num_field(body, "expires_at_height")?,
                    },
                    maker: usdm_decider::whir_rec_block::MakerHalfPublic {
                        nullifier: limbs4(body, "nullifier")?,
                        leaf_commit: limbs4(body, "leaf_commit")?,
                        payout_cm: limbs4(body, "payout_cm")?,
                    },
                    maker_bytes: json_str_field(body, "maker_bytes_hex")
                        .and_then(|h| hex_decode(&h))?,
                    // ⛔ AN ORDER WITHOUT ITS PAYOUT NOTE IS UNFILLABLE — refused HERE rather than
                    // discovered at fill. Only the maker can produce these bytes (they sealed the note
                    // to their own one-time key), and the settlement gate binds the credited note to
                    // `payout_cm`. `?` on the parse means a post without them is BAD_REQUEST.
                    payout_note: json_str_field(body, "payout_note_hex")
                        .and_then(|h| hex_decode(&h))
                        .filter(|n| n.len() >= 32)?,
                    // ⛔ DB-150 — AN ORDER WITHOUT ITS MEMBERSHIP CROSS-BIND CAN NEVER SETTLE, so it is
                    // refused at the post rather than discovered at the fill. Only the maker can build
                    // the proof that their own input note is in this chain's note frontier.
                    membership_carrier: json_str_field(body, "membership_carrier_hex")
                        .and_then(|h| hex_decode(&h))
                        .filter(|c| !c.is_empty())?,
                    membership_tip: json_str_field(body, "membership_tip_hex")
                        .and_then(|h| hex_decode(&h))
                        .filter(|t| crate::node::Node::membership_endpoint_len_ok(t.len()))?,
                    // ⭐ DB-273 §19.6 L3: the MAKER's payout owner (its OLI clue), chosen by the maker and carried by the
                    // order. A post without one is BAD_REQUEST: its payout would be filed for nobody.
                    payout_clue: json_str_field(body, "payout_clue_hex")
                        .and_then(|h| hex_decode(&h))
                        .filter(|c| !c.is_empty() && c.len() <= crate::peg_in_tx::OWNER_CLUE_MAX)?,
                })
            })();
            let Some(parsed) = parsed else {
                return (400, err_json("BAD_REQUEST"));
            };
            // ⭐⭐⭐ DB-402 R4 — ONE ENCODING FEEDS EVERY BOOK. This node rests the order decoded from the SAME bytes it
            // publishes (gossip + the `Class::OrderPost` object), never the parsed request. DB-401 lived in the seam
            // between the two: the publisher rested the request (bind present) while every peer rested the wire (bind
            // dropped by `OrderWire::of`), so the publisher's book looked right in every single-node test and every
            // other book was hollow. Resting the round-tripped wire makes a field the wire drops break THIS node too.
            // ROOT-LAYER: the wire bytes are the one object every other book is built from (gossip arm + block-carried
            // OrderPost apply), so the publisher's book is produced from them too — no second producer exists.
            // MEASURED: DB-401 sim-20261006-190157 — publisher's book held the bind, node 1's held none, fill refused.
            // MUST-STAY-GREEN: dex_cross_party_scenarios::db401_*, rpc_http /post_order route pins, order_post_tx::.
            // An encode or exact-decode failure is a refusal that names itself, never an empty publish.
            let wire_bytes = match postcard::to_stdvec(&crate::order_book::OrderWire::of(&parsed)) {
                Ok(b) => b,
                Err(_) => return (400, err_json("ORDER_WIRE_ENCODE_FAILED")),
            };
            let Some(wire) = crate::chain_object::decode_exact::<crate::order_book::OrderWire>(&wire_bytes) else {
                return (400, err_json("ORDER_WIRE_NOT_ONE_ENCODING"));
            };
            let order = wire.clone().into_order();
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐ DB-407 — AN ORDER RESTS ONLY ON A BIND THE FILL DOOR WILL ADMIT: the maker half's membership, at the same
            // `Admit` door the fill asks (`Node::order_post_bind_verdict`). A lot whose record is not folded here answers
            // the fill's own retry code (409, nothing rested); a bind naming no canonical record is a wrong post (422).
            match g.node().order_post_bind_verdict(&order) {
                crate::node::MemberVerdict::Member => {}
                crate::node::MemberVerdict::Pending => {
                    return (
                        409,
                        "{\"status\":\"REJECTED\",\"reason\":\"MEMBERSHIP_NOT_FOLDED_YET\",\"error\":\"MEMBERSHIP_NOT_FOLDED_YET\",\
                         \"detail\":\"the lot's record is not folded on this node yet — nothing rested; retry after the fold\"}"
                            .to_string(),
                    )
                }
                _ => return (422, err_json("MEMBERSHIP_REFUSED")),
            }
            match g.node_mut().post_order(order) {
                Ok(level) => {
                    // ⭐⭐⭐ AN ORDER THAT RESTS ON ONE NODE MUST REACH THE MESH. Without this the book is
                    // NODE-LOCAL and a maker is only visible to takers who happened to pick the same node
                    // — not an exchange, and a decentralization break (your ability to trade would depend
                    // on guessing your counterparty's node). Broadcast ONLY on a genuinely new rest: a
                    // duplicate never reaches here, so the gossip cannot loop.
                    // ⭐⭐⭐ AN ORDER IS CHAIN STATE, NOT GOSSIP. Broadcasting it is how a taker hears about
                    // it quickly; PUBLISHING it is what makes two nodes hold the same book.
                    // PROVEN 2026-09-04 (`mature_chain_invariants`): a maker rested an order on A, A then
                    // produced four blocks and B grafted EVERY ONE, and B still did not serve it. Nothing
                    // was withheld — the book simply was not derived from the chain, so two honest nodes
                    // with identical chains served different exchanges, with no fill involved at all.
                    // A trader acts on the book, so a per-node book is a per-node exchange.
                    //
                    // The order therefore rides the same path a spend does. No new block field and no fork:
                    // an order is a transaction, and `tx_ids` already carries transactions.
                    // ⛔⛔⛔ FRAMED AS ITS CLASS, NOT AS A RAW WIRE BLOB — and that one difference is
                    // whether any peer ever applies it. This published `postcard(OrderWire)` directly, so
                    // `chain_object::unframe` returned None for it, `apply_chain_objects_of` skipped it,
                    // and the `Class::OrderPost` apply seam never ran on ANY node. The object rode blocks
                    // as a tx id and changed no peer's book: the publish was real and the APPLICATION was
                    // missing, which is why `Class::OrderPost = 2` has had an `admissible` arm since the
                    // enum was written and no producer and no apply path to go with it.
                    //
                    // That is the 2026-09-03 shape with the burn removed: a book entry alive on one node
                    // and absent on another, so the same maker's lot can be filled twice while both nodes
                    // self-verify correctly. The I-CP refutation built to catch it could not fire, because
                    // a node fed only the blocks derived no book to disagree with.
                    {
                        // The RAW wire still feeds the fast epidemic lane below — that is how a taker
                        // hears about an offer in seconds. The FRAMED object is what makes two nodes hold
                        // the same book; the two are complementary, not alternatives.
                        let b = wire_bytes;
                        let bits = g.node().mempool().required_stamp_bits();
                        let tx = crate::order_post_tx::as_pq_tx(&wire.clone().into_order(), bits);
                        if let Err(e) = g.submit_tx(tx) {
                            eprintln!(
                                "[order-post] ⛔ rested locally but the mempool REFUSED the transaction \
                                 ({e:?}) — this order will exist on this node and nowhere else, which is \
                                 the per-node-book class"
                            );
                        }
                        let _ = g.broadcast_order(b);
                    }
                    (
                        200,
                        format!("{{\"status\":\"OK\",\"resting\":true,\"level\":{level}}}"),
                    )
                }
                // Every refusal names its gate — a maker must learn WHY their order is not resting.
                Err(e) => {
                    use crate::order_book::PostRefusal as R;
                    let why = match e {
                        R::ProofRefused => "PROOF_REFUSED",
                        R::AlreadyExpired => "ALREADY_EXPIRED",
                        R::MalformedTerms => "MALFORMED_TERMS",
                        R::Duplicate => "DUPLICATE",
                        R::LevelFull => "LEVEL_FULL",
                        // DB-384: the maker's lot is spent in this node's view — a filled or cancelled offer is dead
                        R::MakerSpent => "MAKER_SPENT",
                        R::PayoutNoteMismatch => "PAYOUT_NOTE_MISMATCH",
                        R::MissingPayoutOwner => "MISSING_PAYOUT_OWNER",
                        // DB-401: the book door's own bind check (this route's parse requires it first, so a gossiped or
                        // block-carried offer is where it fires).
                        R::MissingMembershipBind => "MISSING_MEMBERSHIP_BIND",
                    };
                    (422, err_json(why))
                }
            }
        }
        ("POST", "/book_level") | ("GET", "/book_level") => {
            fn limbs3(body: &str, field: &str) -> Option<[u64; 3]> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                if b.len() != 24 {
                    return None;
                }
                // NOT §AG CLASS 9: `[u64; 3]` by type, source checked to exactly 8 × 3 — no lane count.
                Some(core::array::from_fn(|i| {
                    u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0u8; 8]))
                }))
            }
            let (Some(a), Some(b2), Some(level)) = (
                limbs3(body, "asset_a"),
                limbs3(body, "asset_b"),
                json_num_field(body, "level"),
            ) else {
                return (400, err_json("BAD_REQUEST"));
            };
            if level >= crate::order_book::LATTICE_LEVELS as u64 {
                return (400, err_json("LEVEL_OUT_OF_RANGE"));
            }
            let pair = crate::order_book::PairKey::of(a, b2);
            let (orders, empty) = {
                let g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node().book_level(pair, level as u32)
            };
            // ⛔ THE SERVED SHAPE IS CONSTANT. `slots` is always LEVEL_SLOTS and `empty` is what remains,
            // so a level holding orders and a level nobody touched answer identically in shape — polling
            // the book reveals neither depth nor activity. The entries themselves are offers, which a
            // taker must be able to read to trade at all.
            let mut items = Vec::new();
            for o in &orders {
                // ONE digest wire form on the DEX surface: the canonical 32-byte injective encoding,
                // which is what `/post_order` and `/submit_order_fill` decode with `cm_bytes_to_root`.
                // (This was raw LE lanes — 64 bytes at eight lanes — while the two decoders required 32:
                // the book served what no route could read back.)
                let hex4 = |v: &crate::spend_frontier::Digest4| -> String {
                    hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(*v))
                };
                items.push(format!(
                    "{{\"lot\":{},\"pay_b\":{},\"expires_at_height\":{},\"nullifier\":\"{}\",\"leaf_commit\":\"{}\",\"payout_cm\":\"{}\",\"maker_bytes_hex\":\"{}\",\"payout_note_hex\":\"{}\",\"membership_carrier_hex\":\"{}\",\"membership_tip_hex\":\"{}\",\"payout_clue_hex\":\"{}\"}}",
                    o.terms.lot,
                    o.terms.pay_b,
                    o.terms.expires_at_height,
                    hex4(&o.maker.nullifier),
                    hex4(&o.maker.leaf_commit),
                    hex4(&o.maker.payout_cm),
                    hex_encode(&o.maker_bytes),
                    hex_encode(&o.payout_note),
                    // DB-150: the maker's membership bind travels with the offer — only the maker can
                    // build it, and a taker cannot settle without it.
                    hex_encode(&o.membership_carrier),
                    hex_encode(&o.membership_tip),
                    // DB-273 §19.6 L3: the maker's payout owner, served with the order's other public terms. It
                    // links the payout only to its own order (a fresh clue per order), which the fill already does.
                    hex_encode(&o.payout_clue)
                ));
            }
            // ⛔⛔⛔ SERVE THE RATE THIS NODE WILL ENFORCE. The taker's conservation constraint is
            //    `value_in == pay_b + fee + change`, with `fee` derived from `order_fill_fee_bps`, and
            //    `execute_order_fill` verifies it against THIS node's live governance value. A taker that
            //    GUESSED the rate seals a change note for a different amount than its own proof commits
            //    to: at best the fill is refused, at worst it settles against a commitment whose preimage
            //    the taker does not hold — change that exists on-chain and can never be spent.
            //
            // ROOT-LAYER: the rate is PRODUCED here, by node governance (`params().order_fill_fee_bps`),
            //    and consumed here, by `verify_order_fill`. Publishing it from the producer is the only
            //    placement that cannot drift. The read-layer alternative — a constant compiled into the
            //    wallet — is a COPY of a runtime-tunable value: the day governance moves the rate, every
            //    wallet holding the old copy starts building halves this node refuses, and the wallets
            //    are not the layer that changed. It is a property of settlement, so it travels WITH the
            //    book a taker builds against: one round trip, one source of truth, and the rate a taker
            //    used is by construction the rate this node verifies.
            //
            // MEASURED: before → live node :27780, `POST /book_level` returned
            //    `{"status":"OK","level":0,"slots":32,"empty":32,"orders":[]}` — HTTP 200, ZERO
            //    occurrences of any fee field, while the same node enforces `order_fill_fee_bps = 10`
            //    (0.10%) inside `execute_order_fill`. A taker had no way to learn the rate it would be
            //    judged by, so on a `pay_b = 6_500_000` rung its change was overstated by exactly the
            //    6_500 unit fee. After → the identical call carries `"fill_fee_bps":10`, and the wallet
            //    derives change through the same `protocol_fee` the circuit uses, so the sealed change
            //    note and the proof's `change_cm` bind one value instead of two.
            //
            // MUST-STAY-GREEN: the shape-constancy this endpoint is built on — `slots` is always
            //    LEVEL_SLOTS and `empty` is always served, so a busy level and an untouched one stay
            //    indistinguishable; the added field is identical for every pair, level and caller, so it
            //    is constant across exactly the responses that were already constant and leaks nothing.
            //    Also the existing `/book_level` round-trip test, which parses this JSON field-by-field.
            let fill_fee_bps = {
                let g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node().params().order_fill_fee_bps
            };
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"level\":{level},\"slots\":{},\"empty\":{empty},\"fill_fee_bps\":{fill_fee_bps},\"orders\":[{}]}}",
                    crate::order_book::LEVEL_SLOTS,
                    items.join(",")
                ),
            )
        }
        ("POST", "/submit_order_fill") => {
            // Fail-closed on any malformed/missing field: a fill that cannot even parse is refused
            // (400) before it touches the node — never a defaulted limb.
            //
            // ⛔ ONE CONVERSION, THE CANONICAL ONE (the engine's own rule at `execute_order_fill`,
            // which writes its tags as `leaf_to_cm_bytes(digest)`): every digest field — a value the
            // maker's or taker's PROVER produced and the composed proof is verified against — goes
            // hex(32B) → `cm_bytes_to_root`, the INJECTIVE decode of that form. A raw LE read here was
            // a SECOND encoding of the same nullifier, which is how one note gets two nullifier forms.
            // ⛔⛔⛔ §AI: NOT `cm_bytes_to_leaf`. Since §AG that is a HASH, so this door handed the
            // engine `hash(the digest)` as every public input — the composed proof could never verify
            // and nothing could settle through this route. A digest the chain produced round-trips
            // through the canonical pair; a 32-byte value that is not canonical came from nowhere and
            // is refused here (400), never laundered into some digest.
            // CHAIN-PUBLISH-REVIEWED: a wire-field parser (hex → digest), a read of the request; the
            // fill it feeds is published by `execute_order_fill` (`ingest_tx` of the fill object).
            fn limbs4(body: &str, field: &str) -> Option<crate::spend_frontier::Digest4> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                let arr = <[u8; 32]>::try_from(b.as_slice()).ok()?;
                crate::spend_frontier::cm_bytes_to_root(&arr)
            }
            // Asset tags are plain u64 triples (the wallet's balance-map keys), 24 LE bytes on the wire.
            fn limbs3(body: &str, field: &str) -> Option<[u64; 3]> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                if b.len() != 24 {
                    return None;
                }
                // NOT §AG CLASS 9: `[u64; 3]` by type, source checked to exactly 8 × 3 — no lane count.
                Some(core::array::from_fn(|i| {
                    u64::from_le_bytes(b[i * 8..i * 8 + 8].fixed())
                }))
            }
            fn note(body: &str, field: &str) -> Option<Vec<u8>> {
                json_str_field(body, field)
                    .and_then(|s| hex_decode(&s))
                    .filter(|b| b.len() >= 32)
            }
            let parsed = (|| {
                let maker_carrier =
                    json_str_field(body, "maker_carrier").and_then(|s| hex_decode(&s))?;
                let taker_carrier =
                    json_str_field(body, "taker_carrier").and_then(|s| hex_decode(&s))?;
                let maker = usdm_decider::whir_rec_block::MakerHalfPublic {
                    nullifier: limbs4(body, "maker_nullifier")?,
                    leaf_commit: limbs4(body, "maker_leaf_commit")?,
                    payout_cm: limbs4(body, "maker_payout_cm")?,
                };
                let taker = usdm_decider::whir_rec_block::TakerHalfPublic {
                    nullifier: limbs4(body, "taker_nullifier")?,
                    leaf_commit: limbs4(body, "taker_leaf_commit")?,
                    change_cm: limbs4(body, "taker_change_cm")?,
                    payout_cm: limbs4(body, "taker_payout_cm")?,
                };
                let terms = usdm_decider::whir_rec_block::OrderTerms {
                    lot: json_num_field(body, "lot")?,
                    pay_b: json_num_field(body, "pay_b")?,
                    asset_a: limbs3(body, "asset_a")?,
                    asset_b: limbs3(body, "asset_b")?,
                    expires_at_height: json_num_field(body, "expires_at_height")?,
                };
                let maker_payout_note = note(body, "maker_payout_note")?;
                let taker_payout_note = note(body, "taker_payout_note")?;
                let taker_change_note = note(body, "taker_change_note")?;
                // ⭐ DB-150 — THE TWO MEMBERSHIP CROSS-BINDS. Each half must prove its INPUT note is in
                // this chain's note frontier; a fill without both is refused before anything burns.
                let hexf = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h)).unwrap_or_default();
                let mm_c = hexf("maker_membership_carrier_hex");
                let mm_t = hexf("maker_membership_tip_hex");
                let tm_c = hexf("taker_membership_carrier_hex");
                let tm_t = hexf("taker_membership_tip_hex");
                Some((
                    maker_carrier,
                    maker,
                    taker_carrier,
                    taker,
                    terms,
                    maker_payout_note,
                    taker_payout_note,
                    taker_change_note,
                    (mm_c, mm_t, tm_c, tm_t),
                ))
            })();
            let Some((mc, maker, tc, taker, terms, m_note, t_note, c_note, (mm_c, mm_t, tm_c, tm_t))) =
                parsed
            else {
                return (400, err_json("MALFORMED_FILL"));
            };
            // ⭐ DB-273 §19.6 L3 — THE THREE OWNERS, each an OLI clue, never a receive address:
            // - slots 1–2, the TAKER's payout and change: its own clue records from the one codec, keyed to those two
            //   notes in that order (`clues_keyed_to_notes`, whole or not at all). The reply's `clues_filed` states that
            //   count, which is what the wallet consumes its indices on.
            // - slot 0, the MAKER's payout: copied below from the order the MAKER posted (this node's book, filled from
            //   `Class::OrderPost`), NEVER taken from the taker — before, the taker's request named the maker's owner
            //   (`maker_addr`), so a taker could file the maker's payout under an address the maker cannot restore.
            // A missing taker list leaves empty slots, which the engine refuses (MissingOwner) before anything burns.
            let (t_payout_clue, t_change_clue) =
                match clues_keyed_to_notes(body, &[t_note.as_slice(), c_note.as_slice()]).as_deref() {
                    Some([p, c]) => (p.clone(), c.clone()),
                    _ => (Vec::new(), Vec::new()),
                };
            let clues_filed = if t_payout_clue.is_empty() { 0 } else { 2 };

            // The settlement publishes itself now: `execute_order_fill` admits the transaction where the
            // state actually changes, so the runtime, a wallet path and this route all get the guarantee
            // instead of only whoever remembered to publish. Publishing here as well would put the same
            // trade in the mempool twice.
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                // CHAIN-OBJECT: `Class::OrderPost` — the maker's own order carries its payout clue into this book.
                let Some(maker_clue) = g.node().order_payout_clue(maker.nullifier) else {
                    // Not in this node's book (not yet gossiped here, filled, or expired): refused HERE rather than
                    // take the maker's owner from anyone else. A race, not a wrong submission — retry where it rests.
                    return (409, err_json("ORDER_NOT_IN_BOOK"));
                };
                let maker_bind = (!mm_c.is_empty() && !mm_t.is_empty()).then(|| (mm_c.clone(), mm_t.clone()));
                let taker_bind = (!tm_c.is_empty() && !tm_t.is_empty()).then(|| (tm_c.clone(), tm_t.clone()));
                g.node_mut().execute_order_fill(
                    &mc, &maker, &tc, &taker, &terms, &m_note, &t_note, &c_note,
                    [maker_clue, t_payout_clue, t_change_clue],
                    [maker_bind, taker_bind],
                )
            };
            use crate::node::OrderFillOutcome as O;
            match outcome {
                O::Settled => (
                    200,
                    format!("{{\"status\":\"OK\",\"verdict\":\"SETTLED\",\"clues_filed\":{clues_filed}}}"),
                ),
                // A submission that is WRONG (not a race): the composed proof, terms, or shape is bad.
                O::ProofRefused => (422, err_json("PROOF_REFUSED")),
                O::SelfDealing => (422, err_json("SELF_DEALING")),
                O::MissingOwner => (422, err_json("MISSING_OWNER")),
                // The supplied notes are not the notes the proof attests — a WRONG submission, not a race.
                O::PayoutNoteMismatch => (422, err_json("PAYOUT_NOTE_MISMATCH")),
                // DEX-GRID: a lot, price or expiry off the protocol grid — a WRONG submission, not a race.
                O::OffGrid => (422, err_json("OFF_GRID_TERMS")),
                // DB-150: a half that did not prove its input note is on this chain.
                O::MembershipRefused => (422, err_json("MEMBERSHIP_REFUSED")),
                // A half's record is not folded HERE yet: a race the fold resolves, not a wrong submission — retry.
                O::MembershipPending => (
                    409,
                    "{\"status\":\"REJECTED\",\"reason\":\"MEMBERSHIP_NOT_FOLDED_YET\",\"error\":\"MEMBERSHIP_NOT_FOLDED_YET\",\
                     \"detail\":\"a half's input record is not folded on this node yet — nothing was burned or written; \
                     retry after the fold\"}"
                        .to_string(),
                ),
                // A submission that LOST a race or aged out: correct shape, stale state.
                O::Expired => (409, err_json("ORDER_EXPIRED")),
                O::OrderAlreadyFilled => (409, err_json("ORDER_ALREADY_FILLED")),
                O::TakerNoteSpent => (409, err_json("TAKER_NOTE_SPENT")),
                // ⛔ THE FILL COULD NOT BE ADMITTED AS A TRANSACTION, SO NOTHING WAS WRITTEN.
                //
                // This is the 2026-09-03 double-fill shape caught at the door: a settlement that cannot
                // travel would apply on this node alone, and two honest nodes each self-verifying the same
                // fill is exactly how a maker's lot paid out twice. 503 rather than 4xx because the
                // submission is not wrong — the node could not publish it — so the caller should retry;
                // and the body says plainly that nothing settled, because a caller that reads this as a
                // success is the failure mode the variant exists to prevent.
                O::NotPublished => (
                    503,
                    "{\"status\":\"ERROR\",\"error\":\"NOT_PUBLISHED\",\"detail\":\"The fill was                      NOT admitted as a transaction, so NOTHING was burned, credited or settled. A fill that                      cannot travel would settle on this node alone — the double-fill shape — so it is                      refused outright. Retry.\"}"
                        .to_string(),
                ),
            }
        }
        ("POST", "/submit_asset_create") => {
            // ⭐⭐⭐ THE FIRST STEP OF THE ASSET JOURNEY, AND IT HAD NO DOOR AT ALL (§AR).
            // `Class::AssetCreate` had no framing site outside `#[cfg(test)]`, so no user could create an
            // asset by any route — while `dsol::all_asset_types_unlimited_no_growth_and_trustless`
            // registered 6,000 DESCRIPTORS and its name read as proof that every asset type worked.
            //
            // Fail-closed on any malformed field. The id is RECOMPUTED by the publisher and by every
            // grafting node (`derived_id`) — a claimed id is never taken, because claiming another
            // asset's identity is how you mint into it.
            // CHAIN-PUBLISH-REVIEWED: `publish_asset_create` admits the framed object as a transaction;
            // every node registers it from the block's own bytes.
            let parsed = (|| {
                let kind = match json_str_field(body, "kind").as_deref() {
                    Some("nft") => crate::asset_tx::AssetKind::Nft,
                    Some("token") | None => crate::asset_tx::AssetKind::Token,
                    _ => return None,
                };
                let symbol = json_str_field(body, "symbol")?;
                let name = json_str_field(body, "name")?;
                if symbol.is_empty() || name.is_empty() {
                    return None;
                }
                let logo = json_str_field(body, "logo_hex")
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .unwrap_or([0u8; 32]);
                let dk = match kind {
                    crate::asset_tx::AssetKind::Nft => crate::dsol::DsolKind::Nft,
                    _ => crate::dsol::DsolKind::Token,
                };
                // ⭐⭐⭐ THE CREATOR IS THE CALLER'S OWN KEY, and it is bound into the asset's identity.
                // ⛔ The node does NOT invent one: an asset whose creator the node chose would be an asset
                // the node could mint into. A creation naming no creator is refused.
                let creator_pubkey = json_str_field(body, "creator_pubkey").and_then(|h| hex_decode(&h))?;
                if creator_pubkey.is_empty() {
                    return None;
                }
                let mut c = crate::asset_tx::AssetCreateTx {
                    kind,
                    symbol: symbol.clone(),
                    name: name.clone(),
                    logo,
                    bytecode: crate::dsol::compile(dk, &symbol, &name).bytecode,
                    creator: crate::pqauth::pubkey_id(&creator_pubkey),
                    asset_id: [0u8; 32],
                    // ⭐ §BR-14: the creator's burn of the symbol's price — built and proven in the creator's wallet (it holds
                    // the note), verified here (Admit) and on every node at the fold. Every field is required.
                    fee: {
                        let hx = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h)).filter(|b| !b.is_empty());
                        let b32 = |k: &str| hx(k).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                        crate::asset_tx::CreationFee {
                            nullifier: b32("fee_nullifier")?,
                            leaf_commit: b32("fee_leaf_commit")?,
                            carrier: hx("fee_carrier_hex")?,
                            membership_carrier: hx("fee_membership_carrier_hex")?,
                            membership_tip: hx("fee_membership_tip_hex")?,
                            change_note: hx("fee_change_note_hex")?,
                            change_clue: hx("fee_change_clue_hex")?,
                        }
                    },
                    // §12.6: the picture's own bytes, when the creator puts them on the chain. Its rules are the
                    // creation's (`AssetCreateTx::decode`, re-run on the object just below).
                    art: match json_str_field(body, "art_hex") {
                        Some(h) if !h.is_empty() => hex_decode(&h)?,
                        _ => Vec::new(),
                    },
                    // A-F34: the asset's whole supply, minted by the creation itself (the creator's wallet builds and
                    // signs it; every field is then required). Absent: a creation that mints nothing.
                    supply: match json_str_field(body, "supply_note_hex") {
                        Some(note_hex) if !note_hex.is_empty() => {
                            let hx = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h)).filter(|b| !b.is_empty());
                            Some(crate::asset_tx::CreationSupply {
                                amount: json_num_field(body, "supply_amount")?,
                                note: hex_decode(&note_hex)?,
                                mint_carrier: hx("supply_carrier_hex")?,
                                owner_clue: hx("supply_owner_clue_hex")?,
                                creator_pubkey: creator_pubkey.clone(),
                                creator_sig: hx("supply_creator_sig")?,
                                collection: json_str_field(body, "collection").map(|s| crate::directory::canon_collection(&s)).unwrap_or_default(),
                            })
                        }
                        _ => None,
                    },
                };
                c.asset_id = c.derived_id();
                // the route builds the object from fields, so it runs the object's own decode over what it built: a
                // picture that is not this asset's own, or a malformed handle, is refused here as it is at every door
                crate::asset_tx::AssetCreateTx::decode(&c.encode())
            })();
            let Some(c) = parsed else {
                return (400, err_json("MALFORMED_ASSET_CREATE"));
            };
            let asset_id = hex_encode(&c.asset_id);
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_asset_create(&c)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    format!("{{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"asset_id\":\"{asset_id}\",\"detail\":\"The creation was admitted to the pool and will travel. The fee burn and the asset are decided on every node when the block carrying it folds, not now.\"}}"),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"ASSET_CREATE_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        // ⭐ §BR-12 L1 — publish a DSOL contract deploy the wallet built and signed (`dsol_deploy_tx::DsolDeployTx`, framed).
        ("POST", "/submit_dsol_deploy") => {
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| match crate::chain_object::unframe(&b) {
                    Some((crate::chain_object::Class::DsolDeploy, p)) => crate::dsol_deploy_tx::DsolDeployTx::decode(p),
                    _ => None,
                });
            let Some(d) = parsed else {
                return (400, err_json("MALFORMED_DSOL_DEPLOY"));
            };
            let cid = hex_encode(&d.cid());
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_dsol_deploy(&d)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    format!("{{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"cid\":\"{cid}\",\"detail\":\"The deploy was admitted to the pool and will travel. Its fee burn and the contract's state leaf are decided on every node when the block carrying it folds, not now.\"}}"),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"DSOL_DEPLOY_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        // ⭐ §BR-12 L2 — publish a proven DSOL contract call the wallet built and signed (`dsol_call_tx::DsolCallTx`, framed).
        ("POST", "/submit_dsol_call") => {
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| match crate::chain_object::unframe(&b) {
                    Some((crate::chain_object::Class::DsolCall, p)) => crate::dsol_call_tx::DsolCallTx::decode(p),
                    _ => None,
                });
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_DSOL_CALL"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_dsol_call(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    format!("{{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The call was admitted to the pool and will travel. Its fee, its effects and the contract's new storage root are decided on every node when the block carrying it folds, not now.\"}}"),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"DSOL_CALL_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        // ⭐ §BR-12 L3 — publish the deployer's signed, tighten-only publisher-fee update (`dsol_fee_update_tx`, framed).
        ("POST", "/submit_dsol_fee_update") => {
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| match crate::chain_object::unframe(&b) {
                    Some((crate::chain_object::Class::DsolFeeUpdate, p)) => crate::dsol_fee_update_tx::DsolFeeUpdateTx::decode(p),
                    _ => None,
                });
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_DSOL_FEE_UPDATE"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_dsol_fee_update(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (200, "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The fee cut was admitted to the pool and will travel; it applies on every node when the block carrying it folds.\"}".to_string()),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"DSOL_FEE_UPDATE_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/submit_sat_delegation") => {
            // ⭐ §BR-3 17.3 — the holder's wallet builds the conversion (it holds the burned note); this door decodes it, the
            // publisher re-checks it at the Admit door, and every node decides it at the fold.
            // CHAIN-PUBLISH-REVIEWED: `publish_sat_delegation` admits the framed object as a transaction.
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| crate::sat_delegation_tx::SatDelegationTx::decode(&b));
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_SAT_DELEGATION"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_sat_delegation(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (200, "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The conversion was admitted to the pool; every node decides it when the block carrying it folds.\"}".to_string()),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"SAT_DELEGATION_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/submit_bounty_payout") => {
            // ⭐ §BR-10 — the custody quorum's signed bounty (any custodian assembles it); this door decodes it, the publisher
            // judges it against its state, and every node decides it at the fold.
            // CHAIN-PUBLISH-REVIEWED: `publish_bounty_payout` admits the framed object as a transaction.
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| crate::bounty_payout_tx::BountyPayoutTx::decode(&b));
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_BOUNTY_PAYOUT"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_bounty_payout(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (200, "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The bounty was admitted to the pool; every node pays it when the block carrying it folds.\"}".to_string()),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"BOUNTY_PAYOUT_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/submit_bond_yield_claim") => {
            // ⭐ §BR-3 17.6 — a validator's wallet builds its own-weight yield claim (it holds the vote key); this door decodes it,
            // the publisher judges it against its state, and every node decides it at the fold.
            // CHAIN-PUBLISH-REVIEWED: `publish_bond_yield_claim` admits the framed object as a transaction.
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| crate::bond_yield_claim_tx::BondYieldClaimTx::decode(&b));
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_BOND_YIELD_CLAIM"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_bond_yield_claim(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (200, "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The claim was admitted to the pool; every node pays it when the block carrying it folds.\"}".to_string()),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"BOND_YIELD_CLAIM_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/submit_asset_mint") => {
            // ⭐⭐⭐ THE SECOND STEP, ALSO DOORLESS UNTIL NOW.
            //
            // ⛔ THE CARRIER IS THE AUTHORITY, NOT THE DECLARED AMOUNT. `credit_is_authorised` requires
            // the mint carrier to open the credited note to THIS amount in THIS asset; without it a
            // minter simply chooses what it receives. Refused here before publication and again on every
            // grafting node before any credit.
            // CHAIN-PUBLISH-REVIEWED: `publish_asset_mint` admits the framed object as a transaction.
            // ⭐ DB-273 §19.6 L3: the credited note's OLI clue — the ONLY owner this door reads, and the creator's
            // signature covers its digest (`asset_mint_msg` v2). A mint without one is malformed.
            let owner_clue = owner_clue_field(body);
            let parsed = (|| {
                // ⛔⛔⛔ THE MINT CARRIES ITS OWN AUTHORISATION. Before this, `AssetMintTx` had no
                // signature and `AssetCreateTx` had no creator, so ANY caller could mint unlimited supply
                // of ANY asset and issue the same NFT twice. The wallet signs `asset_tx::asset_mint_msg`
                // with the creating key; every node rebuilds the asset's identity from that key and
                // refuses a mint into an asset it did not create.
                Some(crate::asset_tx::AssetMintTx {
                    creator_pubkey: json_str_field(body, "creator_pubkey")
                        .and_then(|h| hex_decode(&h))
                        .filter(|b| !b.is_empty())?,
                    creator_sig: json_str_field(body, "creator_sig")
                        .and_then(|h| hex_decode(&h))
                        .filter(|b| !b.is_empty())?,
                    symbol: json_str_field(body, "symbol")?,
                    asset_name: json_str_field(body, "asset_name")?,
                    asset_id: json_str_field(body, "asset_id")
                        .and_then(|h| hex_decode(&h))
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())?,
                    kind: match json_str_field(body, "kind").as_deref() {
                        Some("nft") => crate::asset_tx::AssetKind::Nft,
                        Some("token") | None => crate::asset_tx::AssetKind::Token,
                        _ => return None,
                    },
                    amount: json_num_field(body, "amount")?,
                    // ⭐ THE REGISTRY MEMBERSHIP PATH the minter self-built from the PUBLIC creation
                    // stream. Concatenated 32-byte siblings and a bit per level; the node re-derives the
                    // leaf from the descriptor itself and folds this to its own registry root.
                    registry_path: json_str_field(body, "registry_path_hex")
                        .and_then(|h| hex_decode(&h))
                        .map(|b| {
                            b.chunks_exact(32)
                                .filter_map(|c| <[u8; 32]>::try_from(c).ok())
                                .map(|d| crate::spend_frontier::cm_bytes_to_leaf(&d))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                    registry_dirs: json_str_field(body, "registry_dirs")
                        .map(|t| t.chars().map(|c| c == '1').collect::<Vec<bool>>())
                        .unwrap_or_default(),
                    note: json_str_field(body, "note_hex")
                        .and_then(|h| hex_decode(&h))
                        .filter(|b| b.len() >= crate::spend_frontier::NOTE_CM_BYTES)?,
                    mint_carrier: json_str_field(body, "mint_carrier_hex")
                        .and_then(|h| hex_decode(&h))
                        .filter(|b| !b.is_empty())?,
                    owner_clue: owner_clue?,
                    // finding A-F24: the picture digest the asset's identity binds (absent = none), so the mint rebuilds
                    // the id the creation registered; a digest that is not whole is a malformed mint
                    logo: match json_str_field(body, "logo_hex") {
                        Some(h) if !h.is_empty() => hex_decode(&h).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())?,
                        _ => [0u8; 32],
                    },
                    // §12.6: the collection the creator files the asset under (their signature covers it)
                    collection: json_str_field(body, "collection").map(|s| crate::directory::canon_collection(&s)).unwrap_or_default(),
                })
            })();
            let Some(m) = parsed else {
                return (400, err_json("MALFORMED_ASSET_MINT"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_asset_mint(&m)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The mint was admitted to the pool and will travel. The supply is credited when a block carrying it grafts, not now.\"}".to_string(),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"ASSET_MINT_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/submit_asset_spend") => {
            // ⭐⭐⭐ THE PRODUCER SIDE OF §AK — the entry that makes a minted asset spendable by a person.
            //
            // §AK closed the transfer OBJECT and its graft-side door, and left this open: `Class::AssetSpend`
            // had no framing site outside `#[cfg(test)]`, so the chain could create an asset, mint it, and
            // verify a transfer it had no way to receive. Found again by the seam census (§AN) as a class.
            //
            // Fail-closed on any malformed/missing field: a transfer that cannot parse is refused (400)
            // before it touches the node — never a defaulted limb.
            //
            // ⛔⛔⛔ §AI: EVERY DIGEST FIELD TAKES `cm_bytes_to_root`, THE INJECTIVE DECODE — never
            // `cm_bytes_to_leaf`, which has been a HASH since §AG. These are values the spender's PROVER
            // produced and the carriers are verified against; hashing them here would hand the door
            // `hash(the digest)` as every public input, no carrier could ever verify, and nothing could
            // transfer through this route. A 32-byte value that is not canonical came from nowhere.
            // CHAIN-PUBLISH-REVIEWED: a wire-field parser plus `execute_asset_spend`, which publishes the
            // transfer as an ordinary transaction (`ingest_tx`); the burn rides that transaction's own
            // nullifier lane, so it travels to every node.
            fn limbs4(body: &str, field: &str) -> Option<crate::spend_frontier::Digest4> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                let arr = <[u8; 32]>::try_from(b.as_slice()).ok()?;
                crate::spend_frontier::cm_bytes_to_root(&arr)
            }
            fn blob(body: &str, field: &str) -> Option<Vec<u8>> {
                json_str_field(body, field).and_then(|s| hex_decode(&s)).filter(|b| !b.is_empty())
            }
            fn note(body: &str, field: &str) -> Option<Vec<u8>> {
                json_str_field(body, field).and_then(|s| hex_decode(&s)).filter(|b| b.len() >= 32)
            }
            // ⭐ DB-273 §19.6 L3: each output's owner is its OLI clue, from the one clue-list codec keyed to the two notes
            // in the carrier's order — never a receive address. A missing or misaligned list is malformed: an output
            // filed for nobody is money no seed restore finds.
            let parsed = (|| {
                let nf = json_str_field(body, "nullifier")
                    .and_then(|s| hex_decode(&s))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())?;
                let (n0, n1) = (note(body, "note0")?, note(body, "note1")?);
                let owner_clues = clues_keyed_to_notes(body, &[n0.as_slice(), n1.as_slice()])?;
                Some(crate::asset_tx::AssetSpendTx {
                    notes: [n0, n1],
                    nullifier: nf,
                    leaf_commit: limbs4(body, "leaf_commit")?,
                    validity_carrier: blob(body, "validity_carrier")?,
                    membership_carrier: blob(body, "membership_carrier")?,
                    member_tuple: blob(body, "member_tuple").unwrap_or_default(), // §19: the member leg's tuple
                    named_record: json_num_field(body, "named_record")?,
                    tip_prev: limbs4(body, "tip_prev")?,
                    tip_root: limbs4(body, "tip_root")?,
                    tip_acc: limbs4(body, "tip_acc")?,
                    owner_clues,
                    slot_tag: json_str_field(body, "slot_tag").and_then(|s| hex_decode(&s)).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()),
                })
            })();
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_ASSET_SPEND"));
            };
            // ⛔ THE OBJECT'S OWN DECODE IS THE SHAPE AUTHORITY, NOT THIS PARSER. A transfer this route
            // accepted but `AssetSpendTx::decode` would refuse is one that could never be applied by a
            // grafting peer — refuse it here rather than publish a transaction nothing can act on.
            if crate::asset_tx::AssetSpendTx::decode(&t.encode()).is_none() {
                return (400, err_json("MALFORMED_ASSET_SPEND"));
            }
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().execute_asset_spend(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => {
                    // ⛔ "PUBLISHED" IS NOT "APPLIED", AND THE BODY SAYS SO. The credit and the burn happen
                    // when a block carrying this transfer grafts — on every node. A caller that reads an
                    // admission as a settlement is the failure mode this wording exists to prevent.
                    (200, "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The transfer \
was admitted to the pool and will travel. The note is burned and the outputs are credited when a block \
carrying it grafts, not now.\"}".to_string())
                }
                // Refused by the rule every grafting node applies — a WRONG submission, not a race.
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"ASSET_SPEND_REFUSED\",\"detail\":\"{why}\"}}")),
                // The spent note's record is not folded HERE yet: a race, not a wrong submission — retry after the fold.
                A::Pending => asset_pending_answer(),
                // ⛔ The node could not publish it, so NOTHING was written. 503: the submission is not
                // wrong — a transfer that cannot travel would apply here alone and the note would be spent
                // again on every other node, so it is refused outright. Retry.
                A::NotPublished => (
                    503,
                    "{\"status\":\"ERROR\",\"error\":\"NOT_PUBLISHED\",\"detail\":\"The transfer \
was NOT admitted as a transaction, so NOTHING was burned or credited. A spend that cannot travel would \
apply on this node alone — the double-spend shape — so it is refused outright. Retry.\"}"
                        .to_string(),
                ),
            }
        }
        ("POST", "/submit_sat_bond") => {
            // ⭐ SATOSHI §8.3 — the wallet's custody bond in SAT (`Class::SatBond`): the exact field set of `/submit_asset_spend`
            // plus the seat (`weight`, `vid_hex`, `pubkey_hex`, `sig_hex`). Parity with that door (§9.6 q6): every parse check,
            // the decode round-trip, and PUBLISHED / REFUSED / NOT_PUBLISHED — the one extra check is the signed statement,
            // run inside `sat_bond_refusal` with the weld, the membership cross-bind and the spent set.
            fn limbs4(body: &str, field: &str) -> Option<crate::spend_frontier::Digest4> {
                let b = json_str_field(body, field).and_then(|s| hex_decode(&s))?;
                let arr = <[u8; 32]>::try_from(b.as_slice()).ok()?;
                crate::spend_frontier::cm_bytes_to_root(&arr)
            }
            fn blob(body: &str, field: &str) -> Option<Vec<u8>> {
                json_str_field(body, field).and_then(|s| hex_decode(&s)).filter(|b| !b.is_empty())
            }
            fn note(body: &str, field: &str) -> Option<Vec<u8>> {
                json_str_field(body, field).and_then(|s| hex_decode(&s)).filter(|b| b.len() >= 32)
            }
            let parsed = (|| {
                let b32 = |f: &str| json_str_field(body, f).and_then(|s| hex_decode(&s)).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                let nf = b32("nullifier")?;
                let (n0, n1) = (note(body, "note0")?, note(body, "note1")?);
                // the change note's owner (notes[1]); the locked note is filed by the unbond that returns it
                let mut owner_clues = clues_keyed_to_notes(body, &[n1.as_slice()])?;
                let owner_clue = owner_clues.pop()?;
                Some(crate::sat_bond_tx::SatBondTx {
                    notes: [n0, n1],
                    nullifier: nf,
                    leaf_commit: limbs4(body, "leaf_commit")?,
                    validity_carrier: blob(body, "validity_carrier")?,
                    membership_carrier: blob(body, "membership_carrier")?,
                    // §19 (2026-10-28, lane funds): the member leg's tuple beside the carrier — absent = the one-step
                    // form (a fixture's), which the door still judges until batch 16 retires it.
                    // ROOT-LAYER: the route only carries what the wallet PRODUCED (`membership_bind_for`, its own book);
                    //   the verdict is the door's (`sat_bond_refusal` → the one dispatcher), never the route's.
                    // MEASURED: before — every wallet bond carried `named_record` (which record holds the bonded note) on
                    //   the wire; after — the wallet's bond carries the leg and zeroed record fields (the satoshi/bond
                    //   pins + the journey's T3 bond arm of this landing).
                    // MUST-STAY-GREEN: the one-step bond fixtures (`dd_sat_bond`, fuzz/wire) decode with an empty tuple.
                    member_tuple: blob(body, "member_tuple").unwrap_or_default(),
                    named_record: json_num_field(body, "named_record")?,
                    tip_prev: limbs4(body, "tip_prev")?,
                    tip_root: limbs4(body, "tip_root")?,
                    tip_acc: limbs4(body, "tip_acc")?,
                    weight: json_num_field(body, "weight")?,
                    vid: b32("vid_hex")?,
                    pubkey: blob(body, "pubkey_hex")?,
                    sig: blob(body, "sig_hex")?,
                    owner_clue,
                    // §9 RE-BOND: both halves of the leg or neither (one alone is malformed, never half a re-bond)
                    rebond: match (b32("rebond_nullifier_hex"), b32("rebond_locked_cm_hex")) {
                        (Some(nullifier_locked), Some(locked_cm)) => Some(crate::sat_bond_tx::RebondLeg { nullifier_locked, locked_cm }),
                        (None, None) => None,
                        _ => return None,
                    },
                })
            })();
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_SAT_BOND"));
            };
            if crate::sat_bond_tx::SatBondTx::decode(&t.encode()).is_none() {
                return (400, err_json("MALFORMED_SAT_BOND"));
            }
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(why) = crate::node::objects::sat_bond_tx::sat_bond_refusal(g.node(), &t, crate::respend::MemberDoor::Admit) {
                return (422, format!("{{\"status\":\"ERROR\",\"error\":\"SAT_BOND_REFUSED\",\"detail\":\"{why}\"}}"));
            }
            match g.node_mut().publish_sat_bond(&t) {
                Ok(_) => (
                    200,
                    "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The bond was admitted to the pool and will \
travel. The note is burned, the weight seats and the change is credited when a block carrying it folds on every node, not \
now.\"}"
                        .to_string(),
                ),
                Err(_) => (
                    503,
                    "{\"status\":\"ERROR\",\"error\":\"NOT_PUBLISHED\",\"detail\":\"The bond was NOT admitted as a \
transaction, so NOTHING was burned or seated. Retry.\"}"
                        .to_string(),
                ),
            }
        }
        ("POST", "/json_rpc") => {
            let jmethod = json_str_field(body, "method").unwrap_or_default();
            let (_c, info) = route(rt, "GET", "/get_info", "");
            let height = json_num_field(&info, "height").unwrap_or(0);
            let per_block_slots = crate::cover::BLOCK_FIXED_TX_COUNT as u64;
            let spacing = json_num_field(&info, "target_spacing_ms")
                .unwrap_or(500)
                .max(1);
            let result = match jmethod.as_str() {
                "get_info" => info.clone(),
                "get_block_count" => format!("{{\"count\":{height},\"status\":\"OK\"}}"),
                "get_last_block_header" | "get_block_header_by_height" | "get_block" => {
                    // HONEST-LEDGER FORM (user 2026-08-25: the explorer must show ONLY public DA
                    // info). The old answer FABRICATED a per-height `hash` (blake3 of a label — the
                    // O(1) node retains no per-block history to name) and a constant `reward:0`
                    // dressed as data. A ledger that invents fields is lying even when the values
                    // are harmless; both are REMOVED. What remains is real: the height coordinate,
                    // the spacing-derived timestamp (labeled as such), the CONSTANT cover shape, and
                    // depth. Real block IDs are served by /dag_recent for the span this node holds.
                    let h = json_num_field(body, "height").unwrap_or(height);
                    format!(
                        "{{\"status\":\"OK\",\"block_header\":{{\"height\":{h},\"num_txes\":{per_block_slots},\"tx_per_block\":{per_block_slots},\"timestamp\":{},\"depth\":{}}}}}",
                        h.saturating_mul(spacing) / 1000,
                        height.saturating_sub(h)
                    )
                }
                "get_transactions" => "{\"txs\":[],\"status\":\"OK\"}".to_string(),
                _ => format!(
                    "{{\"status\":\"OK\",\"note\":\"private chain — {} carries no per-tx data\"}}",
                    jmethod
                ),
            };
            (
                200,
                format!("{{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"result\":{result}}}"),
            )
        }
        // ── LETTER — 100%-private P2P messaging (crate::letter). This node is the user's OWN self-custodial PQ
        //    crypto engine (seal/open with ML-KEM-768) + a metadata-blind relay (constant-cover ring, oblivious
        //    scan). Zero classical crypto, zero recipient/volume metadata on the wire. ──
        ("GET", "/letter/identity") => {
            let g = letter_state().lock().unwrap_or_else(|e| e.into_inner());
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"address\":\"{}\"}}",
                    hex_encode(&g.0.encap)
                ),
            )
        }
        ("POST", "/letter/seal") => {
            let to = json_str_field(body, "to").unwrap_or_default();
            let msg = json_str_field(body, "msg").unwrap_or_default();
            let to_bytes = match hex_decode(&to) {
                Some(b) => b,
                None => return (200, err_json("BAD_TO")),
            };
            let g = letter_state().lock().unwrap_or_else(|e| e.into_inner());
            match crate::letter::seal(&to_bytes, &g.0.encap, msg.as_bytes()) {
                Some(blob) => (
                    200,
                    format!("{{\"status\":\"OK\",\"blob\":\"{}\"}}", hex_encode(&blob)),
                ),
                None => (200, err_json("SEAL_FAILED")),
            }
        }
        // ── MonerousD Veil (docs/VEIL-SOVEREIGN-INTERNET-SPEC-20261107.md §3, §4): publish a site, carry its bytes,
        // read them back. Every byte is checked against a root a signed publish anchors (`veil::SiteHost`); these arms
        // only move bytes between this node's own wallet, its site store and its peers.
        ("POST", "/site/publish") => {
            let name = json_str_field(body, "name").unwrap_or_default();
            let version = json_num_field(body, "version").unwrap_or(0);
            let hex_of = |f: &str| json_str_field(body, f).and_then(|h| hex_decode(&h));
            let (Some(root), Some(pubkey), Some(sig)) = (hex_of("root").and_then(|b| crate::hash::Hash32::from_slice(&b)), hex_of("pubkey"), hex_of("sig")) else {
                return (200, err_json("BAD_PUBLISH"));
            };
            if version == 0 || crate::veil::mud_name(&format!("{name}{}", crate::veil::MUD_SUFFIX)).as_deref() != Some(name.as_str()) {
                return (200, err_json("BAD_PUBLISH"));
            }
            let publish = crate::site::SitePublish::new(crate::pqauth::pubkey_id(&pubkey), &name, version, root);
            let outcome = rt.lock().unwrap_or_else(|e| e.into_inner()).publish_site(crate::site::SiteGossip::new(publish, pubkey, sig));
            let word = match outcome {
                crate::site::PublishOutcome::Adopted => "adopted",
                crate::site::PublishOutcome::StaleVersion => "stale",
                crate::site::PublishOutcome::WrongOwner => "wrong_owner",
                crate::site::PublishOutcome::Unauthenticated => "unauthenticated",
            };
            (200, format!("{{\"status\":\"OK\",\"outcome\":\"{word}\"}}"))
        }
        ("POST", "/veil/put") => {
            // this node's own wallet hands over a site's index, then its chunks, after the publish that anchors them
            let hex_of = |f: &str| json_str_field(body, f).and_then(|h| hex_decode(&h));
            let Some(root) = hex_of("root").and_then(|b| crate::hash::Hash32::from_slice(&b)) else {
                return (200, err_json("BAD_ROOT"));
            };
            if !rt.lock().unwrap_or_else(|e| e.into_inner()).node().site_anchored(&root) {
                // BYTES WITH NO NAME (a sale's sealed content): kept here as this wallet's own copy and handed, point to
                // point, to the holders the root's placement names. A holder keeps them only once it has seen them paid
                // for (`veil_lane`), so nothing unpaid is pushed onto the network by this route.
                if !body.contains("\"bare\":true") {
                    return (200, err_json("NOT_ANCHORED"));
                }
                let (n, bytes) = match (hex_of("index"), json_num_field(body, "i"), hex_of("chunk")) {
                    (Some(index), ..) => (crate::veil::WANT_INDEX, index),
                    (None, Some(at), Some(chunk)) => (at, chunk),
                    _ => return (200, err_json("BAD_CHUNK")),
                };
                {
                    let Some(mut host) = crate::veil::host() else {
                        return (200, err_json("NO_SITE_STORE"));
                    };
                    // O1-INFINITY-REVIEWED: one slot of the constant-size site store (`veil::ChunkStore`), as below
                    let taken = if n == crate::veil::WANT_INDEX { host.put_read_index(&root, &bytes) } else { host.put_chunk(&root, n, &bytes, true) };
                    if !taken {
                        return (200, err_json("BAD_CHUNK"));
                    }
                }
                let sent = rt.lock().unwrap_or_else(|e| e.into_inner()).veil_put_to_holders(&root, n, &bytes);
                let (kept, unpaid) = crate::veil_lane::client().put_verdicts(&root, n);
                return (200, format!("{{\"status\":\"OK\",\"sent\":{sent},\"kept\":{kept},\"unpaid\":{unpaid}}}"));
            }
            let frame = {
                let Some(mut host) = crate::veil::host() else {
                    return (200, err_json("NO_SITE_STORE"));
                };
                // O1-INFINITY-REVIEWED: the site store is ONE file of the operator's budget cut into fixed slots
                // (`veil::ChunkStore`); a put takes a free slot or replaces one, so its size is a constant the operator
                // chose and never a function of the chain, the sites or the chunks handed over.
                if let Some(index) = hex_of("index") {
                    let taken = host.put_index(&root, &index); // O1-INFINITY-REVIEWED: one slot of the constant-size store
                    if !taken {
                        return (200, err_json("BAD_INDEX"));
                    }
                    // the chunks this node does not hold yet: the only ones its wallet hands over (an update's
                    // unchanged files are already here under their hashes). PRODUCTION-SCALE-REVIEWED: at most one
                    // entry per chunk of one site's index, which fits one chunk (7,281 entries).
                    let missing: Vec<String> = host.missing(&root).iter().map(u64::to_string).collect();
                    let frame = crate::veil::frame_index(&root, &index);
                    drop(host);
                    rt.lock().unwrap_or_else(|e| e.into_inner()).veil_gossip(frame);
                    return (200, format!("{{\"status\":\"OK\",\"missing\":[{}]}}", missing.join(",")));
                } else {
                    let (Some(at), Some(chunk)) = (json_num_field(body, "i"), hex_of("chunk")) else {
                        return (200, err_json("BAD_CHUNK"));
                    };
                    let taken = host.put_chunk(&root, at, &chunk, true); // O1-INFINITY-REVIEWED: one slot of the constant-size store
                    if !taken {
                        return (200, err_json("BAD_CHUNK"));
                    }
                    crate::veil::frame_chunk(&root, at, &chunk)
                }
            };
            rt.lock().unwrap_or_else(|e| e.into_inner()).veil_gossip(frame);
            (200, "{\"status\":\"OK\"}".to_string())
        }
        ("POST", "/claim_watch") => {
            // goods spec §3.3: this node's own wallet names the spent tags of the downloads it is waiting on and reads
            // back the tags laid beside them (the seller's delivery claim carries the content key there).
            // DIGITAL-CASH-PRIVACY-REVIEWED: this node's own wallet over loopback; the named tags stay in this process
            // (never gossiped, logged or written) and the answer is public chain data.
            let tags_of = |field: &str| -> Option<Vec<[u8; 32]>> {
                let joined = json_str_field(body, field).unwrap_or_default();
                joined.split(',').filter(|h| !h.is_empty()).map(|h| hex_decode(h).and_then(|b| <[u8; 32]>::try_from(b).ok())).collect()
            };
            let (Some(watch), Some(forget)) = (tags_of("spent_tags_hex"), tags_of("forget_hex")) else {
                return (400, err_json("CLAIM_WATCH_BAD_TAG"));
            };
            if watch.len() + forget.len() > crate::claim_watch::WATCH_MAX {
                return (400, err_json("CLAIM_WATCH_TOO_MANY"));
            }
            crate::claim_watch::forget(&forget);
            let found = rt.lock().unwrap_or_else(|e| e.into_inner()).node().claim_tags_beside(&watch);
            let rows: Vec<String> =
                found.iter().map(|(spent, claim)| format!("{{\"spent_tag\":\"{}\",\"claim_tag\":\"{}\"}}", hex_encode(spent), hex_encode(claim))).collect();
            (200, format!("{{\"status\":\"OK\",\"found\":[{}]}}", rows.join(",")))
        }
        ("POST", "/veil/search") => {
            // the Sovereign browser's search: every published site, ranked by what its own front page says
            // (`veil_search`), one page of results at a time like a web search engine's.
            // DIGITAL-CASH-PRIVACY-REVIEWED: asked by this node's own wallet over loopback; the query is matched here and
            // never logged, stored or sent to a peer, and every site listed is public chain data every node holds.
            let query = json_str_field(body, "q").unwrap_or_default();
            let from = usize::try_from(json_num_field(body, "from").unwrap_or(0)).unwrap_or(usize::MAX);
            // PRODUCTION-SCALE-REVIEWED: one results page; a person asks for the next with `from` (default 10, at most 50)
            let count = usize::try_from(json_num_field(body, "count").unwrap_or(10).clamp(1, 50)).unwrap_or(10);
            let sites = rt.lock().unwrap_or_else(|e| e.into_inner()).node().published_mud();
            let hits = {
                let mut host = crate::veil::host();
                crate::veil_search::search(sites, host.as_deref_mut(), &query)
            };
            let host = crate::veil::host();
            let rows: Vec<String> = hits
                .iter()
                .skip(from)
                .take(count)
                .map(|h| {
                    let root = h.site.publish.manifest_root;
                    let total = host.as_ref().and_then(|x| x.total_len(&root));
                    format!(
                        "{{\"name\":\"{}\",\"version\":{},\"root\":\"{}\",\"total_len\":{},\"title\":\"{}\",\"snippet\":\"{}\",\"score\":{}}}",
                        json_escape(&h.site.name),
                        h.site.publish.version,
                        hex_encode(root.as_bytes()),
                        total.map_or("null".to_string(), |t| t.to_string()),
                        json_escape(&h.title),
                        json_escape(&h.snippet),
                        h.score
                    )
                })
                .collect();
            (200, format!("{{\"status\":\"OK\",\"total\":{},\"from\":{from},\"sites\":[{}]}}", hits.len(), rows.join(",")))
        }
        ("POST", "/veil/index") => {
            // a version's index as this node holds it, for its own wallet: what an update is compared against
            let Some(root) = json_str_field(body, "root").and_then(|h| hex_decode(&h)).and_then(|b| crate::hash::Hash32::from_slice(&b)) else {
                return (200, err_json("BAD_ROOT"));
            };
            match crate::veil::host().and_then(|h| h.index(&root)) {
                Some(index) => (200, format!("{{\"status\":\"OK\",\"index\":\"{}\"}}", hex_encode(&index))),
                None => (200, err_json("NOT_HELD")),
            }
        }
        ("POST", "/veil/site") => {
            // a name's site as this node's own state has it: nothing is asked of anyone
            let host_name = json_str_field(body, "host").unwrap_or_default();
            let Some(site) = rt.lock().unwrap_or_else(|e| e.into_inner()).node().resolve_mud(&host_name) else {
                return (200, "{\"status\":\"OK\",\"site\":null}".to_string());
            };
            let root = site.publish.manifest_root;
            let (total, held) = crate::veil::host().map_or((None, false), |h| (h.total_len(&root), h.knows(&root)));
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"site\":{{\"name\":\"{}\",\"owner\":\"{}\",\"version\":{},\"root\":\"{}\",\"index_held\":{held},\"total_len\":{}}}}}",
                    json_escape(&site.name),
                    hex_encode(&site.owner),
                    site.publish.version,
                    hex_encode(root.as_bytes()),
                    total.map_or("null".to_string(), |t| t.to_string())
                ),
            )
        }
        ("POST", "/veil/file") => {
            // one piece of one file of a site, read from this node's store. When the site is not here it is asked for
            // PRIVATELY (`veil_lane`: two holders, one point-function share each, each on a circuit of its own): no
            // holder learns what this node's owner is looking at, or that it was this node that looked.
            let (host_name, path) = (json_str_field(body, "host").unwrap_or_default(), json_str_field(body, "path").unwrap_or_default());
            let from = json_num_field(body, "from").unwrap_or(0);
            let Some(site) = rt.lock().unwrap_or_else(|e| e.into_inner()).node().resolve_mud(&host_name) else {
                return (200, err_json("NO_SUCH_SITE"));
            };
            let root = site.publish.manifest_root;
            let read = {
                let Some(mut host) = crate::veil::host() else {
                    return (200, err_json("NO_SITE_STORE"));
                };
                match host.locate(&root, &path) {
                    Ok(None) => return (200, err_json("NOT_FOUND")),
                    Ok(Some((start, size))) => {
                        // one piece is at most 2 MiB, so a reply stays far under the request cap whatever the file's size
                        let len = size.saturating_sub(from).min(2 * 1024 * 1024);
                        host.read(&root, start + from.min(size), len).map(|bytes| (size, bytes))
                    }
                    Err(gap) => Err(gap),
                }
            };
            match read {
                Ok((size, bytes)) => (200, format!("{{\"status\":\"OK\",\"size\":{size},\"from\":{from},\"hex\":\"{}\"}}", hex_encode(&bytes))),
                Err(gap) => {
                    let missing = match gap {
                        crate::veil::Gap::Index => 1,
                        crate::veil::Gap::Chunks(list) => list.len(),
                    };
                    crate::veil_lane::client().want(root);
                    (200, format!("{{\"status\":\"NOT_HELD\",\"missing\":{missing},\"fetching\":true}}"))
                }
            }
        }
        ("POST", "/veil/host") | ("GET", "/veil/host") => {
            let (used, budget, sites, paid, pages) = crate::veil::host().map_or((0, 0, 0, 0, 0), |h| {
                let (used, budget, sites) = h.stats();
                (used, budget, sites, h.paid_count(), h.pages_used())
            });
            let paid_here = rt.lock().unwrap_or_else(|e| e.into_inner()).node().veil_terms().is_some();
            // how many items this node read privately from other holders since it started: its own count, no site named
            let read_privately = crate::veil_lane::client().items_read;
            (200, format!("{{\"status\":\"OK\",\"used\":{used},\"pages_used\":{pages},\"budget\":{budget},\"sites\":{sites},\"paid_sites\":{paid},\"paid_to_wallet\":{paid_here},\"read_privately\":{read_privately}}}"))
        }
        ("POST", "/veil/holders") => {
            // PUBLISHER: who holds the bytes `root` binds, what each asks to be paid at, and each one's share of the
            // price. Holders not asked yet are asked now (one private ask each); the wallet calls again for the rest.
            // DIGITAL-CASH-PRIVACY-REVIEWED: this node's own wallet over loopback; what is answered is each holder's
            // PUBLIC address keys (its operator's choice to publish) and a price that is a function of a byte count.
            let Some(root) = json_str_field(body, "root").and_then(|h| hex_decode(&h)).and_then(|b| crate::hash::Hash32::from_slice(&b)) else {
                return (200, err_json("BAD_ROOT"));
            };
            let total_len = json_num_field(body, "total_len").unwrap_or(0);
            let holders = rt.lock().unwrap_or_else(|e| e.into_inner()).veil_holder_terms(&root);
            let rows: Vec<String> = holders
                .iter()
                .map(|(id, terms)| match terms {
                    Some(Some(t)) => format!(
                        "{{\"id\":\"{}\",\"answered\":true,\"spk\":\"{}\",\"scan_ek\":\"{}\"{}}}",
                        json_escape(id),
                        hex_encode(&t.spk),
                        hex_encode(&t.scan_ek),
                        // the one-time receive address the holder reserved for this answer (AUDIT F11): where it is paid
                        t.address().map_or(String::new(), |a| format!(",\"address\":\"{}\"", json_escape(&a)))
                    ),
                    Some(None) => format!("{{\"id\":\"{}\",\"answered\":true}}", json_escape(id)),
                    None => format!("{{\"id\":\"{}\",\"answered\":false}}", json_escape(id)),
                })
                .collect();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"price_atomic\":{},\"share_atomic\":{},\"holders\":[{}]}}",
                    crate::veil::storage_price_atomic(total_len),
                    crate::veil_lane::price_share(total_len, holders.len()),
                    rows.join(",")
                ),
            )
        }
        ("POST", "/veil/pay_seed") => {
            // PUBLISHER: the 32 bytes the note that pays `holder` for these bytes is made from, for a secret the wallet
            // drew. Computed here so the wallet and the holder cannot disagree on its spelling.
            // DIGITAL-CASH-PRIVACY-REVIEWED: this node's own wallet over loopback; nothing is stored or sent.
            let hex_of = |f: &str| json_str_field(body, f).and_then(|h| hex_decode(&h));
            let (Some(root), Some(secret)) = (hex_of("root").and_then(|b| crate::hash::Hash32::from_slice(&b)), hex_of("secret").and_then(|b| <[u8; 32]>::try_from(b).ok())) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let holder = json_str_field(body, "holder").unwrap_or_default();
            let seed = crate::veil_lane::pay_seed(&root, json_num_field(body, "total_len").unwrap_or(0), &holder, &secret);
            (200, format!("{{\"status\":\"OK\",\"seed\":\"{}\"}}", hex_encode(&seed)))
        }
        ("POST", "/veil/paid") => {
            // PUBLISHER: tell one holder of the payment just made to it (sealed to that holder; one private ask).
            // DIGITAL-CASH-PRIVACY-REVIEWED: this node's own wallet over loopback; the secret leaves this process only
            // sealed to the holder it pays, and is not stored or logged here.
            let hex_of = |f: &str| json_str_field(body, f).and_then(|h| hex_decode(&h));
            let (Some(root), Some(secret)) = (hex_of("root").and_then(|b| crate::hash::Hash32::from_slice(&b)), hex_of("secret").and_then(|b| <[u8; 32]>::try_from(b).ok())) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let e = crate::veil_lane::Evidence { root, total_len: json_num_field(body, "total_len").unwrap_or(0), amount: json_num_field(body, "amount").unwrap_or(0), secret };
            let holder = json_str_field(body, "holder").unwrap_or_default();
            let sent = rt.lock().unwrap_or_else(|e| e.into_inner()).veil_tell_paid(&holder, &e);
            (200, format!("{{\"status\":\"OK\",\"sent\":{sent},\"notices_read\":{}}}", crate::veil_lane::client().notices_read))
        }
        ("POST", "/veil/blob") => {
            // READER: bytes of the run `root` binds, from this node's own store. When they are not here they are asked
            // for PRIVATELY (`veil_lane`: two holders, one point-function share each, each on a circuit of its own), so
            // no holder learns what was read or which node read it; the wallet asks again until they have arrived.
            let Some(root) = json_str_field(body, "root").and_then(|h| hex_decode(&h)).and_then(|b| crate::hash::Hash32::from_slice(&b)) else {
                return (200, err_json("BAD_ROOT"));
            };
            let from = json_num_field(body, "from").unwrap_or(0);
            let read = {
                let Some(mut host) = crate::veil::host() else {
                    return (200, err_json("NO_SITE_STORE"));
                };
                match host.total_len(&root) {
                    Some(total) => host.read(&root, from.min(total), total.saturating_sub(from).min(2 * 1024 * 1024)).map(|bytes| (total, bytes)),
                    None => Err(crate::veil::Gap::Index),
                }
            };
            match read {
                Ok((size, bytes)) => (200, format!("{{\"status\":\"OK\",\"size\":{size},\"from\":{from},\"hex\":\"{}\"}}", hex_encode(&bytes))),
                Err(_) => {
                    crate::veil_lane::client().want(root);
                    (200, "{\"status\":\"NOT_HELD\",\"fetching\":true}".to_string())
                }
            }
        }
        ("POST", "/veil/audit") => {
            // ANYONE on this node: ask the holders of `root` to show the piece this node's tip draws for each, and read
            // back what earlier asks were answered. A holder that dropped the bytes cannot show its piece.
            let Some(root) = json_str_field(body, "root").and_then(|h| hex_decode(&h)).and_then(|b| crate::hash::Hash32::from_slice(&b)) else {
                return (200, err_json("BAD_ROOT"));
            };
            let asked = rt.lock().unwrap_or_else(|e| e.into_inner()).veil_ask_proofs(&root);
            let rows: Vec<String> = crate::veil_lane::client().proofs_of(&root).iter().map(|(h, shown)| format!("{{\"holder\":\"{}\",\"shown\":{shown}}}", json_escape(h))).collect();
            (200, format!("{{\"status\":\"OK\",\"asked\":{asked},\"answers\":[{}]}}", rows.join(",")))
        }
        ("POST", "/letter/send") => {
            let blob = json_str_field(body, "blob").unwrap_or_default();
            let bytes = match hex_decode(&blob) {
                Some(b) => b,
                None => return (200, err_json("BAD_BLOB")),
            };
            // Relay locally AND gossip across the mesh, so the sealed letter reaches its recipient on ANY node
            // (the recipient's wallet reads it from that node's /letter/inbox). Opaque blob — no key here.
            let relayed = {
                let mut g = match rt.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                g.gossip_letter(bytes)
            };
            (200, format!("{{\"status\":\"OK\",\"relayed\":{relayed}}}"))
        }
        ("GET", "/letter/inbox") => {
            let g = letter_state().lock().unwrap_or_else(|e| e.into_inner());
            let slots: Vec<String> =
                g.1.inbox()
                    .iter()
                    .map(|b| format!("\"{}\"", hex_encode(b)))
                    .collect();
            (
                200,
                format!("{{\"status\":\"OK\",\"slots\":[{}]}}", slots.join(",")),
            )
        }
        ("GET", "/letter/acc") => {
            // The LETTER ACCUMULATOR — a flat 32-byte commutative sum over every carried letter_set this
            // node folded ABOVE its last adopted certified boundary (the DSYNC-inherited baseline covers
            // everything at or below it). CONTRACT: nodes sharing an adopt lineage converge on one value;
            // it is a certified-sync summary, NOT a global instant-parity probe (side-blocks a peer never
            // saw pre-boundary can lag until merged). A letter's PROOF surface is its block anchor
            // (letter_set, id-bound) — never this figure.
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let acc = rt.node().letter_acc();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"letter_acc\":\"{}\"}}",
                    hex_encode(&acc)
                ),
            )
        }
        ("POST", "/letter/history") | ("GET", "/letter/history") => {
            // HISTORY RESTORE — a fixed page of the ledger's letter columns by frontier ordinal. The wallet
            // walks pages from its cursor, opens obliviously (only its own letters authenticate), and verifies
            // each opened blob's commitment against the block-anchored letter_set — so a fresh device restores
            // the FULL chat history from the 24 words with no local store and nothing trusted. PRIVACY: the
            // range is the same chain-progress coordinate the note backfill already serves — selector-
            // independent (identical bytes to every asker), naming no recipient, sender, or count of REAL
            // mail (columns interleave with rows that hold none, and blobs are opaque ciphertext).
            // cons: none — ONE call is a FIXED 64-ordinal page (LETTER_CMS_PER_BLOCK, a protocol shape
            // constant): 64 indexed map reads per request, no term in height/blocks/notes; the CALLER's
            // cursor loop is the restoring wallet's own one-time walk (its cost belongs to the restorer,
            // page-by-page, resumable — the same model as the existing note-restore pages).
            let from = match json_str_field(body, "from").and_then(|s| s.parse::<u64>().ok()) {
                Some(v) => v,
                None => 0,
            };
            let rt = match rt.lock() { Ok(g) => g, Err(p) => p.into_inner() };
            let node = rt.node();
            let mut entries: Vec<String> = Vec::new();
            for ord in from..from.saturating_add(crate::letter::LETTER_CMS_PER_BLOCK as u64) {
                let Some(rid) = node.da_addr_at_ordinal(ord) else { continue };
                let col = node.da_letters_wire(rid);
                if !col.is_empty() {
                    entries.push(format!("{{\"ord\":{},\"letters\":\"{}\"}}", ord, hex_encode(&col)));
                }
            }
            (200, format!("{{\"status\":\"OK\",\"from\":{},\"page\":{},\"entries\":[{}]}}",
                from, crate::letter::LETTER_CMS_PER_BLOCK, entries.join(",")))
        }
        ("POST", "/letter/blob") | ("GET", "/letter/blob") => {
            // Fetch ONE sealed blob by its on-chain commitment — the backfill read. SELF-VERIFYING at the
            // fetcher (`letter_cm(blob) == cm`, and the cm rides a block), so a lying peer cannot forge mail.
            // The blob is opaque end-to-end ciphertext; serving it reveals nothing the gossip didn't.
            let cm_hex = match json_str_field(body, "cm") {
                Some(s) => s,
                None => String::new(),
            };
            let cm_bytes = match hex_decode(&cm_hex) {
                Some(b) => b,
                None => return (200, err_json("BAD_CM")),
            };
            let cm: [u8; 32] = match <[u8; 32]>::try_from(cm_bytes.as_slice()) {
                Ok(a) => a,
                Err(_) => return (200, err_json("BAD_CM")),
            };
            match letter_blob_of(&cm) {
                Some(blob) => (
                    200,
                    format!("{{\"status\":\"OK\",\"blob\":\"{}\"}}", hex_encode(&blob)),
                ),
                None => (200, "{\"status\":\"OK\",\"blob\":null}".to_string()),
            }
        }
        // Oblivious scan, done in-process: open the ENTIRE constant-cover window with OUR OWN key and return only
        // the letters that authenticate (the rest are cover — they never open). One O(1) call instead of the
        // front-end round-tripping 64 opens, so the inbox renders instantly (sub-1s). The node reading the owner's
        // OWN mail on the owner's OWN device is self-custodial — no plaintext ever leaves this machine.
        ("GET", "/letter/scan") => {
            let g = letter_state().lock().unwrap_or_else(|e| e.into_inner());
            let mut msgs = Vec::new();
            for blob in g.1.inbox() {
                if let Some(o) = crate::letter::open(&blob, g.0.secret()) {
                    let msg = String::from_utf8_lossy(&o.msg)
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    msgs.push(format!(
                        "{{\"from\":\"{}\",\"msg\":\"{}\"}}",
                        hex_encode(&o.from),
                        msg
                    ));
                }
            }
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"cover_slots\":{},\"messages\":[{}]}}",
                    crate::letter::RELAY_SLOTS,
                    msgs.join(",")
                ),
            )
        }
        ("POST", "/letter/open") => {
            let blob = json_str_field(body, "blob").unwrap_or_default();
            let bytes = match hex_decode(&blob) {
                Some(b) => b,
                None => return (200, err_json("BAD_BLOB")),
            };
            let g = letter_state().lock().unwrap_or_else(|e| e.into_inner());
            match crate::letter::open(&bytes, g.0.secret()) {
                Some(o) => {
                    let msg = String::from_utf8_lossy(&o.msg)
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"");
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"opened\":true,\"from\":\"{}\",\"msg\":\"{}\"}}",
                            hex_encode(&o.from),
                            msg
                        ),
                    )
                }
                None => (200, "{\"status\":\"OK\",\"opened\":false}".to_string()),
            }
        }
        // ── FAUCET (crate::faucet) — a TESTNET-ONLY minter that ISSUES valueless test USDm on demand and records
        //    it on the ordinary note path, so a dev (or a brand-new wallet) can get coins to move. Gated on the
        //    node's own testnet genesis (403 on mainnet). `drip` with no `to` issues to the tool's demo key so the
        //    node can scan the landed balance (self-verify); with `to`, it issues straight to the caller's wallet. ──
        ("GET", "/faucet/identity") => {
            let Some(fs) = faucet_state() else { return faucet_off() };
            let g = fs.lock().unwrap_or_else(|e| e.into_inner());
            let net = if node_network_is_testnet(rt) {
                "testnet"
            } else {
                "mainnet"
            };
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"network\":\"{}\",\"demo\":\"{}\"}}",
                    net,
                    hex_encode(g.demo_ek())
                ),
            )
        }
        ("GET", "/faucet/status") => {
            let Some(fs) = faucet_state() else { return faucet_off() };
            let g = fs.lock().unwrap_or_else(|e| e.into_inner());
            let net = if node_network_is_testnet(rt) {
                "testnet"
            } else {
                "mainnet"
            };
            let ready = node_network_is_testnet(rt); // issues only on testnet; 403 elsewhere
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"network\":\"{}\",\"ready\":{},\"demo_balance\":{}}}",
                    net,
                    ready,
                    g.demo_balance()
                ),
            )
        }
        // ⛔⛔⛔ COMPILE-TIME GATED, NOT RUNTIME GATED — STRONGER THAN THE FAUCET'S 403.
        //
        // `btc_watch::inject_confirmed_for_test` is `#[cfg(any(test, feature = "bridge-test-oracle"))]`,
        // so this arm and the function behind it are ABSENT FROM A RELEASE BINARY. There is no free-mint
        // bypass to reach in production, not even a refused one.
        //
        // ⭐ WHY THE FUNCTIONAL TIER NEEDS A DOOR AT ALL: `inject_confirmed_for_test` is a library call,
        // and §CU's journeys drive SEPARATE OPERATING-SYSTEM PROCESSES over sockets — which is the whole
        // point of that tier and precisely why an in-process fixture cannot stand in for it. Without a
        // door, no real node process can be told what its own watcher would have read from Bitcoin.
        //
        // ⛔ AND IT DOES NOT WEAKEN THE GATE IT ENABLES. This supplies the EXTERNAL CHAIN'S data, exactly
        // what a Bitcoin regtest supplies to a functional test. `Node::execute_peg_in`'s deposit-
        // confirmation gate still runs unchanged, per node, from that node's OWN reader: no confirmed
        // deposit ⇒ no self-attestation ⇒ the ≥2/3 threshold fails ⇒ NO mint. What is under test control
        // is the foreign chain, never the node's decision about it — and the refutation arms of the
        // journey assert exactly that by withholding the injection.
        #[cfg(feature = "bridge-test-oracle")]
        ("POST", "/dev/inject_confirmed_deposit") => {
            let address = json_str_field(body, "address").unwrap_or_default();
            let sats = json_num_field(body, "sats").unwrap_or(0);
            if address.is_empty() || sats == 0 {
                return (400, err_json("BAD_REQUEST"));
            }
            crate::btc_watch::inject_confirmed_for_test(&address, sats);
            // DIGITAL-CASH-PRIVACY-REVIEWED: the reply is a fixed status with no address, amount, tag,
            // key or owner echoed back. The inputs are external-chain facts the depositor chose and
            // Bitcoin already publishes; nothing about a USDm note, its value or its owner appears here.
            (200, "{\"status\":\"OK\"}".to_string())
        }
        // Which networks this node may use, which one is carrying it now, and how large the crowd on our network is (`pqmix::crowd`, a
        // count of public relay records every view holds). A choice only decides how bytes travel, so it cannot touch a balance.
        // O2 (lane af57): `floor` is the crowd at which a payment takes our network even with Tor up (`pqmix::ANON_FLOOR`); below it
        // Tor carries a payment while Tor is up, and our network carries it at once while Tor is down. A payment never waits on it.
        ("GET", "/network_choice") => (
            200,
            format!(
                "{{\"choice\":\"{}\",\"carrying\":\"{}\",\"crowd\":{},\"crowd_large\":{},\"floor\":{}}}",
                crate::pqmix::network_choice().name(),
                crate::pqmix::network_state(),
                crate::pqmix::crowd(),
                crate::pqmix::CROWD_LARGE,
                crate::pqmix::ANON_FLOOR
            ),
        ),
        ("POST", "/network_choice") => {
            let choice = json_str_field(body, "choice").and_then(|text| crate::pqmix::NetworkChoice::parse(&text));
            match choice {
                Some(choice) => {
                    crate::pqmix::set_network_choice(choice);
                    (200, format!("{{\"choice\":\"{}\"}}", choice.name()))
                }
                None => (400, err_json("the choice must be auto, tor or own")),
            }
        }
        ("POST", "/faucet/drip") => {
            if !node_network_is_testnet(rt) {
                return (403, err_json("TESTNET_ONLY"));
            }
            let amount = json_num_field(body, "amount").unwrap_or(0);
            let to = json_str_field(body, "to").unwrap_or_default();
            // Who this credit belongs to, for the account index. `b` addresses their bucket; `mlkem` is a
            // PUBLIC key, so the node gains the ability to WRITE that bucket and never to read it.
            // ⭐⭐⭐ KEEP THE WHOLE PARSE — THE LOCATOR IS IN THE ADDRESS AND WAS BEING THROWN AWAY.
            // `parse_address_full` yields `locator`, `loc_salt` and `loc_hint`; mapping to `(b, mlkem)`
            // discarded exactly the fields that make a credited note FINDABLE. See the clue attachment below.
            let recip_parsed = crate::address::parse_address_full(&to);
            let recipient: Option<([u8; 32], Vec<u8>)> =
                recip_parsed.as_ref().map(|p| (p.b, p.mlkem.clone()));
            // ⛔ DB-273 §17 condition (1): a drip NAMED to a recipient must be findable from that recipient's seed, so a
            // recipient with no locator (a raw ek, a locator-free address) is REFUSED before anything is issued — never a
            // note filed nowhere (a burn wearing a default). `to` empty is the node's own demo balance, owned by nobody.
            if !to.is_empty() && recip_parsed.as_ref().and_then(|p| p.locator.as_ref()).is_none() {
                return (
                    200,
                    "{\"status\":\"REFUSED\",\"issued\":0,\"published\":false,\"reason\":\"NO_LOCATOR\",\"detail\":\"the recipient carries no locator, so the credited note could never be found from its seed; send to a wallet receive address\"}".to_string(),
                );
            }
            // ⛔⛔ DB-395: a drip NAMED to a recipient is sealed to the recipient's SPEND KEY, or the faucet that sealed it could
            // spend it and compute its nullifier. A pre-v4 address (or a raw ek) carries none, so it is REFUSED before anything
            // is issued — there is no sealer that takes an address without one.
            if !to.is_empty() && recip_parsed.as_ref().and_then(|p| p.spk).is_none() {
                return (
                    200,
                    "{\"status\":\"REFUSED\",\"issued\":0,\"published\":false,\"reason\":\"NO_SPEND_KEY\",\"detail\":\"the recipient address carries no spend key (a pre-v4 address), so the sealer would hold spend authority over the note; send to a v4 wallet receive address\"}".to_string(),
                );
            }
            // Issue under the faucet lock, then DROP it before touching the node (never hold two locks).
            let note = {
                let Some(fs) = faucet_state() else { return faucet_off() };
                let mut g = fs.lock().unwrap_or_else(|e| e.into_inner());
                if to.is_empty() {
                    g.issue_to_demo(amount) // self-verify path: the node scans the demo balance
                } else {
                    // A v4 wallet receive address: its ML-KEM key and its spend key (both checked above). Fail-closed on
                    // anything malformed.
                    match recip_parsed.as_ref().and_then(|p| p.spk.map(|spk| (p.mlkem.clone(), spk))) {
                        Some((ek, spk)) => g.issue(&ek, &spk, amount),
                        None => None,
                    }
                }
            };
            match note {
                Some(n) => {
                    // ⭐⭐⭐ §BA BRICK 2 — THE DRIP IS A CHAIN OBJECT, NOT A STAGING.
                    //
                    // This handler used to make THREE RAM stagings (`record_account_target`,
                    // `record_note_clue`, `stage_credit_note`) and let the next produced block carry the
                    // note with NO TRANSACTION behind it. That is exactly the shape §BA measured: a note
                    // every peer records and holds unspent on the producer's word alone. The faucet was
                    // the last production path that put a note on chain without a transaction, and the
                    // one sound close for §BA needs the invariant "every carried note is the output of a
                    // transaction under `tx_merkle_root`" to hold with no carve-out.
                    //
                    // So the drip is now a `Class::BridgeCredit` — the same object a peg-in is — published
                    // through the same door (`ingest_tx`), judged by the same rule (`admissible`, which
                    // bounds it by this chain's genesis-derived open-mint allowance: non-zero on a testnet,
                    // ZERO on a value-bearing network, which is also what keeps the faucet off mainnet).
                    // Its account target and locator clue ride the transaction's own sidecars and are
                    // staged when the pool ACCEPTS it — never before, never beside it.
                    //
                    // The CHAIN-ACTION sweep listed `stage_credit_note` and `record_account_target` as
                    // handler-performed transitions with nothing published; this route no longer performs
                    // either.
                    let clue: Vec<u8> = match (recip_parsed.as_ref(), n.len() >= 32) {
                        (Some(p), true) => match p.locator.as_ref() {
                            Some(loc) => match (p.loc_salt.as_ref(), p.loc_hint.as_ref()) {
                                (Some(salt), Some(hint)) => {
                                    crate::oli::tag_clue_bytes_v2(loc, salt, hint)
                                }
                                _ => crate::oli::tag_clue_bytes(loc),
                            },
                            None => {
                                eprintln!(
                                    "[faucet] ⛔ this recipient address carries NO locator — the credited \
                                     note will not enter the locator index and cannot be found from the \
                                     seed alone"
                                );
                                Vec::new()
                            }
                        },
                        _ => Vec::new(),
                    };
                    // The deposit this settles: the faucet's own issuance of THIS note. A re-drip of the
                    // same note is the same deposit, recognisable as such rather than merely the same bytes.
                    let deposit_id = {
                        let mut pre = Vec::with_capacity(20 + 32);
                        pre.extend_from_slice(b"USDMD-FAUCET-DRIP-v1");
                        pre.extend_from_slice(&n[..n.len().min(32)]);
                        *crate::hash::Hash32::hash(&pre).as_bytes()
                    };
                    let credit = crate::bridge_credit_tx::BridgeCreditTx {
                        deposit_id,
                        asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                        amount,
                        note: n.to_vec(),
                        // DB-273 §17: the recipient's clue, INSIDE the object (the frame's id binds it).
                        owner_clue: clue.clone(),
                        attestors: Vec::new(),
                    };
                    let published = {
                        let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                        let bits = g.node().mempool().required_stamp_bits();
                        // ⛔⛔⛔ `submit_tx`, NOT `node_mut().ingest_tx` — THE DIFFERENCE IS WHETHER THE
                        // CREDIT EVER REACHES A SECOND NODE. `ingest_tx` pools it HERE and nothing else;
                        // `submit_tx` pools it and GOSSIPS it (`WireMsg::Tx`), which is the only reason a
                        // peer ever sees it. MEASURED in the ecosystem gate 2026-09-23: the drip pooled
                        // the credit on node 1, node 1 was 84 blocks behind and so (correctly, per
                        // isNearlySynced) built no template, node 2 never heard of it, and the user's
                        // balance stayed 0.00 while THIS DOOR REPORTED `"status":"OK"`. Whether a payment
                        // settled depended on which node the payer reached and whether it won authorship
                        // — a race on block production, not a property of the payment. The comment one
                        // screen up in this same file already names the class: *"which is exactly what
                        // pooling without gossiping produces."*
                        g.submit_tx(credit.as_pq_tx(bits))
                    };
                    match published {
                        Ok(id) => (
                            200,
                            format!(
                                "{{\"status\":\"OK\",\"issued\":{},\"published\":true,\"tx_id\":\"{}\",\"settled\":false,\"detail\":\"credit published as a BridgeCredit chain object; it settles when a block carries it, on every node\",\"note\":\"{}\"}}",
                                amount,
                                id.to_hex(),
                                hex_encode(&n)
                            ),
                        ),
                        Err(e) => {
                            // Fixed string plus the door's own error name — no amount, key or owner.
                            eprintln!(
                                "[faucet] ⛔ the drip's credit object was REFUSED by this node's own \
                                 admission door ({e:?}); nothing was staged and nothing rides a block."
                            );
                            (200, err_json("FAUCET_CREDIT_REFUSED"))
                        }
                    }
                }
                None => (200, err_json("BAD_RECIPIENT")),
            }
        }
        // ⛔ DB-350: `/want_note_record` is DELETED with the ask it raised — a wallet named the commitment of a note it
        // owns, and this node asked a peer for the record BY THAT COMMITMENT, telling the peer which note is whose.
        // An unknown path answers 404; the record a membership read misses is wanted by its public address.
        ("POST", "/recarry_note") => {
            // ⛔ MAINTENANCE: re-carry a STRANDED note (see `Node::recarry_stranded_note` — fail-closed on
            // present, on spent, and on unknown). Inputs are both already-public coordinates: a DA record
            // address and a cm the block's own output_notes list. DIGITAL-CASH-PRIVACY-REVIEWED: reveals
            // no owner, amount or key; answers only OK / a refusal kind.
            let rid = match json_num_field(body, "record_addr") {
                Some(r) => r,
                None => return (200, err_json("MISSING_RECORD_ADDR")),
            };
            let cm = match json_str_field(body, "cm_hex").and_then(|h| hex_decode(&h)) {
                Some(b) if b.len() == 32 => {
                    let mut c = [0u8; 32];
                    c.copy_from_slice(&b);
                    c
                }
                _ => return (200, err_json("BAD_CM_HEX")),
            };
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            match g.node_mut().recarry_stranded_note(rid, cm) {
                Ok(()) => (200, "{\"status\":\"OK\",\"staged\":true}".to_string()),
                Err(e) => (200, err_json(e)),
            }
        }
        ("POST", "/submit_pq_tx") => {
            let hex = match json_str_field(body, "tx_as_hex") {
                Some(h) => h,
                None => return (200, err_json("MISSING_TX_AS_HEX")),
            };
            let blob = match hex_decode(&hex) {
                Some(b) if !b.is_empty() => b,
                _ => return (200, err_json("BAD_HEX")),
            };
            // The carrier blob IS the unit the light decider verifies. Build the mempool tx; the id is
            // the content hash of the blob, so a tampered blob cannot masquerade as another tx. The
            // client (wallet) grinds the #72 anti-spam stamp non-outsourceably and supplies it as
            // `pow_stamp`; absent → 0, which the mempool's stamp gate rejects fail-closed.
            let id = PqTx::content_id(&blob);
            let weight = blob.len() as u32;
            let pow_stamp = json_num_field(body, "pow_stamp").unwrap_or(0);
            // goods spec §9.1: the chain clock the spend's carrier was proven against (`PqTx::clock_ms`); absent → 0, the
            // clock of a transaction whose statement binds none. The door refuses a value off the hour grid or ahead of
            // the chain clock, and the carrier verifies under no other value.
            let clock_ms = json_num_field(body, "clock_ms").unwrap_or(0);
            // The tx's CONFIDENTIAL OUTPUT notes (recipient + change), concatenated 1153-byte payloads. When
            // this tx is grafted into a block they are recorded to the served note index (same generic path as
            // cover/coinbase), so the recipient can locally scan its note. Absent for non-transfer carriers.
            // FAIL CLOSED ON A PRESENT-BUT-UNDECODABLE FIELD. This used to be `.unwrap_or_default()`, which
            // turned ANY decode failure into an EMPTY note set — and an empty note set is not an error anywhere
            // downstream: the tx pools, gossips, is selected and settles perfectly, carrying NO recipient note.
            // The sender gets `status OK`, the block is valid, nothing is ever logged, and the payment simply
            // does not exist for its recipient. A silently-dropped field on the money path must be a REJECTION,
            // never a default — if the caller sent notes we could not read, we must not pretend it sent none.
            let output_notes = match json_str_field(body, "output_notes_hex") {
                None => Vec::new(), // genuinely absent: a non-transfer carrier legitimately has no notes
                Some(h) => match hex_decode(&h) {
                    Some(b) => b,
                    None => return (200, err_json("BAD_OUTPUT_NOTES_HEX")),
                },
            };
            // ⭐ THE NOTES A SUBMIT ACTUALLY CARRIES — the first point at which a payment can become noteless.
            //
            // MEASURED: 175 of 175 produced blocks carried exactly 1,153 note bytes (the constant entropy
            // note); a settling payment carries recipient + change = 2,306. I inferred the cause was cover
            // out-ranking payments in `select_for_template` and built a regression test for it — then ran the
            // NEGATIVE CONTROL twice, with the ordering reverted, and the test passed both times. The
            // hypothesis is REFUTED: selection was never starving payments.
            //
            // So the question moves one hop earlier: does the tx carry output notes when it is ADMITTED? A tx
            // that enters the pool noteless can never contribute notes to a block, and every downstream layer
            // (target lookup, bucket filing, peer adopt, recipient detection) is then starved by construction.
            // This is a fact to read, not another inference.
            //
            // Per-SUBMIT, a rare user-driven event — no per-block bytes. DIGITAL-CASH-PRIVACY-REVIEWED: a
            // BYTE COUNT only. Never a note, cm, amount, key, address or owner.
            eprintln!(
                "[submit-notes] tx carries {} output-note byte(s) ({} whole note(s)); a settling transfer \
                 needs recipient+change",
                output_notes.len(),
                output_notes.len() / 1153
            );
            // The spend's NULLIFIER (4 KoalaBear limbs packed as 32 bytes). The carrier PROVES this is the spent
            // note's TRUE nullifier (welded public), so recording it in the tx lets the mempool + cross-block
            // double-spend gates reject a second spend of the same note. Absent for non-transfer carriers.
            let nullifier_bytes: Option<[u8; 32]> = json_str_field(body, "nullifier_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            // FULLY-PRIVATE MULTI-INPUT spend: the N spent notes' nullifiers, concatenated 32-byte packings. Present
            // (≥2) ⇒ this is a single-tx consolidation of N confidential inputs → 2 outputs; the node records ALL N
            // as spent (each input's double-spend is caught) and verifies via the multi-input carrier gate below.
            let multi_nfs: Vec<[u8; 32]> = json_str_field(body, "nullifiers_hex")
                .and_then(|h| hex_decode(&h))
                .map(|b| {
                    b.chunks_exact(32)
                        .map(|c| {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(c);
                            a
                        })
                        .collect()
                })
                .unwrap_or_default();
            // ⭐ ROW 0 IS THE SPEND'S NULLIFIER (link 62). The TX-level verdict (`Node::send_verdict`, shared with the gossip
            // door) reads the nullifier from the transaction's own tag list — row 0, where the membership binder, the member
            // tuple and the template's spend tuple already read it — so a `nullifier_hex` naming any other tag is a request
            // this door cannot honour as written, refused by name rather than silently re-read.
            if let (Some(nf), Some(row0)) = (nullifier_bytes, multi_nfs.first()) {
                if nf != *row0 {
                    eprintln!("[admit-gate] ⛔ REFUSED a tx whose nullifier_hex is not row 0 of its tag list");
                    return (200, "{\"status\":\"REJECTED\",\"reason\":\"NULLIFIER_NOT_ROW_0\"}".to_string());
                }
            }
            // STAKE-to-earn: the 32-byte note_cm(s) of this tx's output notes being STAKED (locked into the
            // stake accumulator to earn a fee-redistribution share). Empty for a plain transfer.
            let stake_notes = json_str_field(body, "stake_notes_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // ⛔ DB-327 — A STAKE-BEARING TRANSACTION IS REFUSED AT THIS DOOR, BEFORE ANY PROOF IS VERIFIED. Its
            // `stake_notes` (`cm ‖ amount ‖ nullifier`) published the staked AMOUNT and the staked note's FUTURE spend
            // nullifier to every node, so the unstake was linked to the stake; and the stake itself never landed
            // (DB-313: evicted at template) and paid 0 (DB-237 §1). The pool/gossip door refuses the same predicate
            // (`admit_tx_shared`, lane-db224); this arm fails fast and names the reason. The private stake (DB-237)
            // re-opens staking as an ordinary constant-shape spend.
            // ROOT-LAYER: this door is where a client's bytes first become a transaction, so a refusal here means the
            // leaking field is never verified, pooled or gossiped from this node.
            // MEASURED: READ (DB-327: the wallet no longer sends it; any other client still could); pin
            // `db327_a_stake_bearing_submit_is_refused_at_the_door_before_any_proof`.
            // MUST-STAY-GREEN: every body without `stake_notes_hex` reaches the gates it reached before; bonds unchanged.
            if !stake_notes.is_empty() {
                return (
                    422,
                    "{\"status\":\"ERROR\",\"error\":\"STAKE_PAUSED\",\"detail\":\"a stake publishes its amount and its \
                     note's future nullifier, so staking is paused until the private stake (DB-237); nothing was \
                     admitted\"}"
                        .to_string(),
                );
            }
            // ⛔⛔⛔ VALIDATOR BONDS ARE SAT-ONLY (`Node::USDM_BOND_RETIRED`, 2026-10-07): a submit carrying a USDm bond
            // statement (`bond_notes_hex`) is refused HERE, keyed on the field alone, before any proof is verified or any
            // note pooled — legibly, so the wallet says why (the STAKE_PAUSED arm's shape just above). A validator bonds SAT
            // through `/submit_sat_bond`. Privacy: a FIXED string.
            if json_str_field(body, "bond_notes_hex").is_some_and(|h| !h.is_empty()) {
                eprintln!("[admit-gate] ⛔ REFUSED a USDm bond: validator bonds are SAT (/submit_sat_bond)");
                return (422, err_json(crate::node::Node::USDM_BOND_RETIRED));
            }
            // Per-note DETECTION CLUES (oblivious cold-restore), read by THE one clue-list codec (DB-330): whole or
            // not at all. They ride the transaction (`note_clues` below) and are FILED at admission, on this node and
            // on every node that admits the gossiped transaction, under DB-330's rule — a record is filed only for a
            // note this transaction carries as its own output. (The old comment here said "no griefing surface";
            // there was one: nothing checked the cm, and first-writer-wins let a record for ANY note stand.)
            let clue_records: Vec<([u8; 32], Vec<u8>)> = json_str_field(body, "note_clues_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|bytes| crate::node::Node::parse_note_clue_records(&bytes))
                .unwrap_or_default();
            // ⭐ DB-273 §19.7 L4a (2026-09-30): THE ACCOUNT-TARGET INTAKE IS DELETED — `/submit` reads no
            // `account_targets_hex`, carries none on the transaction and files none. A target was `note_cm ‖
            // bucket_id ‖ ek`, and a bucket id is a per-WALLET constant: carried on the tx and the block, it published
            // one wallet's id beside every payment it received and every change it made (`PqTx::account_targets`,
            // `Block::account_targets`, both FILED_OPEN). No wallet reads a bucket since L5 and the wallet builds no
            // target since this landing, so an honest transaction's targets are empty; the field, the header root and
            // the store are deleted at the one re-genesis (L4b). A stale wallet's `account_targets_hex` is ignored.

            // COUPLED-SWAP witness intake: the spender's SELF-BUILT non-membership `InsertWitness` per spent
            // nullifier (postcard-encoded Vec), so `nullifier_witnesses_gate` verifies each against the O(1)
            // `nullifier_acc` root — the node holds NO nullifier tree to consult. Absent / malformed ⇒ empty (a
            // spend then fails the witness-mandatory gate fail-closed; a non-spend cover/coinbase carries none).
            // ⭐ CONSTANT-WIDTH ADMISSION PROOF: one carrier proving EVERY carried tag is either a real spend's
            // nullifier or a correctly-derived decoy (`nf_sparse_air::verify_spend_or_decoy_bytes`), WITHOUT
            // revealing which. This is what lets a tx settle the constant per-tx width: the multi-input gate below
            // asks the spend carrier to prove ALL carried tags are real spends, which a decoy-carrying tx can
            // never satisfy, and telling the node the split would leak the real-input count.
            let spend_or_decoy_proof: Vec<u8> = json_str_field(body, "spend_or_decoy_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // ⭐ DB-223 — the spend input's member-path carrier and its public tuple, when the wallet proved one. ABSENT
            // is the legacy membership door's case; PRESENT but undecodable is refused here, never silently dropped
            // (a spend that sent a carrier must be judged by it). The pool door verifies it (`Node::ingest_tx`).
            let member_field = |name: &str| -> Result<Vec<u8>, ()> {
                match json_str_field(body, name) {
                    None => Ok(Vec::new()),
                    Some(h) => hex_decode(&h).ok_or(()),
                }
            };
            let (member_carrier, member_tuple) = match (member_field("member_carrier_hex"), member_field("member_tuple_hex")) {
                (Ok(c), Ok(t)) if c.is_empty() == t.is_empty() => (c, t),
                _ => return (422, err_json("MEMBER_CARRIER_MALFORMED")),
            };
            let nullifier_witnesses_parsed: Vec<crate::nf_sparse::CompressedCopath> =
                json_str_field(body, "nullifier_witnesses_hex")
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| {
                        crate::chain_object::decode_exact::<Vec<crate::nf_sparse::CompressedCopath>>(&b)
                    })
                    .unwrap_or_default();
            // ⭐⭐⭐ FOLD-NOT-HOLD ABSENCE INTAKE (brick C3, O(1)) — the spender's SELF-MAINTAINED recursive absence
            // carrier per spent nullifier: it maintains ONE self-overwriting proof, folding each new block in O(1)
            // as it arrives (NEVER a genesis→tip walk), and attaches the O(1) proof here. `nullifier_witnesses_gate`
            // verifies each against this node's O(1) A_tip (`verify_nf_absence_chain`) with NO copath and NO held
            // tree. Absent / malformed ⇒ empty (a spend then fails the fold gate fail-closed; a cover/coinbase
            // carries none). ([[project_fold_not_hold_produce_full_design]])
            let nullifier_absence_parsed: Vec<crate::nf_sparse::NfAbsenceWitness> =
                json_str_field(body, "nullifier_absence_hex")
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| {
                        crate::chain_object::decode_exact::<Vec<crate::nf_sparse::NfAbsenceWitness>>(&b)
                    })
                    .unwrap_or_default();
            // ⛔⛔⛔ THE OFF-LOCK `direct_ok` ARM IS DELETED. IT PROVED NOTHING ABOUT THIS TRANSACTION.
            //
            // It read `pqspend_direct_verify_carrier(&blob).is_some()`, i.e. `verify_spend_carrier_bytes` —
            // ONE row-local AIR (`in - out - fee == 0`) whose ENTIRE public input is the CONSTANT
            // `SPEND_CARRIER_DOMAIN`: one field element, with ZERO slots for the nullifier, the output
            // commitments, the anchor root or the chain id. Nothing in that statement names THIS tx, so ONE
            // carrier admitted EVERY transaction — measured with `nullifiers` empty, `output_notes`
            // arbitrary, `bond_notes` / `stake_notes` / `account_targets` / `note_clues` /
            // `membership_leaf_commit` / `membership_tip` all substituted, and across chain ids — all
            // ADMITTED with the SAME proof, whose construction needs NO secret at all (three integers).
            // A tx with EMPTY nullifiers clears the membership gate below vacuously, so this arm alone
            // minted arbitrary `output_notes` out of nothing.
            //
            // ⛔ A DISJUNCTION IS AS STRONG AS ITS WEAKEST ARM. Beside it sat the SOUND arms —
            // `spend_ok` / `multi_ok` / `bond_ok` / `stake_ok`, which weld the anchor root, BOTH output
            // commitments, the nullifier and the membership cross-bind as PUBLIC inputs — so the sound
            // gates never had to run. DELETED AT SOURCE rather than gated around: no honest sender ever
            // produced this carrier (`build_spend_carrier`, the conservation-only producer, had no
            // production caller — only its own tests), so removing the arm refuses exactly the forgeries.
            //
            // cons: the off-lock parallel pre-verify goes with it. That win was real (1-core → cores× on
            // admission) and it is not worth one field element of statement: the arms that remain read
            // `rt.node().spend_frontier_root()` and are therefore on-lock by construction. Recovering the
            // parallelism means hoisting the root read, not restoring an empty proof.
            // ([[project_launch_readiness_program]] · CHARTER §9.6 item 2 — PROOF, named where it runs.)
            // ⭐⭐⭐ THE CLUES RIDE THE TX — see `PqTx::note_clues` for the measured race this removes.
            // Encoded by the SAME codec the staging side parses (DB-330), so the wire form and the map can never drift.
            let carried_clues: Vec<u8> = crate::node::Node::encode_note_clue_records(&clue_records);

            let mut tx = PqTx {
                clock_ms,
                note_clues: carried_clues,
                // DB-273 L4a: no account targets (the intake above is deleted); the field goes at the re-genesis (L4b).
                account_targets: Vec::new(),
                // ⭐⭐⭐ THE SPEND-OR-DECOY CARRIER RIDES THE TRANSACTION — cleared below unless it verified over this
                // transaction's own tag set (`SendArms::cover`), so the producer holds it by construction.
                spend_or_decoy: spend_or_decoy_proof,
                member_carrier,
                member_tuple,
                id,
                blob,
                weight,
                nullifiers: if !multi_nfs.is_empty() {
                    // Multi-input: EVERY spent input's nullifier is recorded so each is protected from re-spend.
                    multi_nfs
                        .iter()
                        .map(|nf| crate::hash::Hash32(*nf))
                        .collect()
                } else {
                    match nullifier_bytes {
                        Some(nf) => vec![crate::hash::Hash32(nf)],
                        // A carrier that spends no note (cover, coinbase) states no tag; every spend-class gate below
                        // requires `nullifier_bytes`, so this arm admits nothing by itself.
                        None => Vec::new(),
                    }
                },
                pow_stamp,
                output_notes,
                stake_notes,
                bond_notes: Vec::new(),
                // COUPLED-SWAP: the spender SELF-BUILT a non-membership `InsertWitness` per nullifier (from the
                // replicated nullifier stream it fetched via /get_nullifier_stream, rebuilt an identical IMT LOCALLY,
                // self-verified vs `nullifier_root()`) and attaches them here (postcard-encoded). The node holds NO
                // nullifier tree for admission — `nullifier_witnesses_gate` verifies each carried witness against the
                // O(1) `nullifier_acc` root. Empty ⇒ a non-spend carrier (cover / coinbase) with no nullifier to gate.
                // ⭐ O(1) NOTE-MEMBERSHIP CARRIER, off the wire. The spender proves its note is a member of
                // this chain in constant size; `membership_gate` below checks it against the node's OWN
                // accumulator. `membership_leaf_commit` is a per-tx COMMITMENT to the spent note's leaf, never
                // the leaf — publishing that would link this spend to the receive that created the note.
                membership_carrier: json_str_field(body, "membership_carrier_hex")
                    .and_then(|h| hex_decode(&h))
                    .unwrap_or_default(),
                membership_tip: json_str_field(body, "membership_tip_hex")
                    .and_then(|h| hex_decode(&h))
                    .unwrap_or_default(),
                membership_folded_through: json_num_field(body, "membership_folded_through")
                    .unwrap_or(0),
                membership_leaf_commit: json_str_field(body, "membership_leaf_commit_hex")
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .unwrap_or([0u8; 32]),
                nullifier_witnesses: nullifier_witnesses_parsed,
                nullifier_absence: nullifier_absence_parsed, // brick C3: O(1) fold absence proofs, spender-self-maintained
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐⭐⭐ THE TX-LEVEL SEND VERDICT (link 62) — the ONE function the gossip door runs too (`Node::send_verdict`:
            // the one-step membership gate and its obligation, the canonical clue list, the spend / multi-input /
            // spend-or-decoy arms, the multi-input-needs-cover refusal, each with its history and its §9.6 answers).
            // This door keeps its JSON reasons. A spend whose spend-or-decoy carrier does not verify over its own tag set is
            // refused whole. MEASURED (real nodes, 2026-11-04, one byte flipped in a real spend's carrier): this door used to
            // strip the carrier and pool the rest under the same id. A stripped spend can never be stated by a block, and the
            // honest spend was then refused `tx already in the pool`: anyone who saw a payment could kill it with one byte.
            let refused = |reason: &str| (200, format!("{{\"status\":\"REJECTED\",\"reason\":\"{reason}\"}}"));
            match rt.node().send_verdict(&tx) {
                Ok(arms) => {
                    if !arms.cover {
                        return refused("SPEND_OR_DECOY_INVALID");
                    }
                }
                Err(crate::node::SendRefusal::MembershipInvalid) => return refused("MEMBERSHIP_PROOF_INVALID"),
                Err(crate::node::SendRefusal::MembershipMissing) => return refused("MEMBERSHIP_PROOF_MISSING"),
                Err(crate::node::SendRefusal::NonCanonicalClues) => return refused("NON_CANONICAL_CLUES"),
                Err(crate::node::SendRefusal::ClockNotReached) => return refused("SPEND_CLOCK_NOT_REACHED"),
                Err(crate::node::SendRefusal::MultiInputNeedsCover) => {
                    return (200, err_json("MULTI_INPUT_NEEDS_COVER_CARRIER:attach spend_or_decoy_hex at the constant width"))
                }
                // `RetiredFormat` cannot reach here (stake and bond bytes are refused at intake above); with `NoArm` it is a
                // send no arm verified.
                // ⛔ STILL OPEN: this answers HTTP 200 and the wallet reads the status, not the body, so a refusal can look
                // like success end to end. 400 is right, but it turned
                // `a_late_clue_is_findable_through_the_real_oli_pir_routes_on_a_verifying_peer` red and nobody established
                // why; the fix is 400 plus whatever that test needs, not the one-character change alone.
                Err(crate::node::SendRefusal::NoArm(_) | crate::node::SendRefusal::RetiredFormat) => {
                    return refused(&json_escape("InvalidProof"))
                }
            }
            // Carrier verified → brief-locked stateful accept (nullifier double-spend + structural) + GOSSIP.
            let out_len = tx.output_notes.len();
            let out_dbg = tx.output_notes.clone();
            let submitted_id = tx.id;
            match rt.submit_tx_prechecked(tx) {
                Ok(h) => {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a pool COUNT only — never a tx id, nullifier or amount.
                    // The RPC answering OK is not proof the tx is POOLED: measured, the producer saw
                    // `pool_left 0` on every block after an accepted send, and the sender's own note stayed
                    // unspent forever. Printing the pool size at the instant of accept separates "admitted then
                    // dropped" from "never admitted despite an OK" — the RPC's word versus the actual state.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a pool count and a BYTE LENGTH only — never a note,
                    // amount, key or owner. A tx pooled with ZERO output notes settles perfectly and pays
                    // NOBODY: the producer records 0 note bytes, the recipient's node has nothing, and the
                    // sender is told OK. That is indistinguishable from success at every layer above.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a COMMITMENT of the payload (blake3, truncated), never
                    // the payload itself — no note, amount, key or owner is recoverable from it. It exists to
                    // answer the one hop still unmeasured: are the bytes the wallet SEALED the same bytes this
                    // node RECORDS? A digest compares them without ever printing a note.
                    eprintln!(
                        "[submit] accepted; pool {} tx(s); {} output-note bytes; payload digest {}",
                        rt.node().mempool().len(),
                        out_len,
                        &hex_encode(crate::hash::Hash32::hash(&out_dbg).as_bytes())[..16]
                    );
                    // ⛔ DB-330: the clues are NOT filed here. Admission already filed the carried ones on this node
                    // (`stage_carried_note_clues`, the ONE filing site, under the rule that a record names this
                    // transaction's own output), and every node that admits the gossiped transaction does the same.
                    // The loop that stood here filed EVERY record, for ANY cm, and gossiped each one mesh-wide.
                    // (DB-273 L4a: the account-target filing that followed it is deleted with the intake.)
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"tx_hash\":\"{}\"}}",
                            hex_encode(h.as_bytes())
                        ),
                    )
                }
                // A wallet whose answer timed out sends the same spend again: it is pooled, and that is what the wallet asked
                // for. Every carried proof of this body verified above, so the pooled copy states it too. BORROWED-FROM Bitcoin
                // Core `sendrawtransaction`, which answers the txid for a transaction already in its mempool.
                Err(crate::mempool::MempoolError::AlreadyKnown) => {
                    (200, format!("{{\"status\":\"OK\",\"tx_hash\":\"{}\"}}", hex_encode(submitted_id.as_bytes())))
                }
                Err(e) => {
                    // ⛔⛔⛔ THE ONLY SILENT EXIT IN THIS HANDLER — A PAYMENT DIES HERE WITH NO LINE.
                    //
                    // Every other branch says something: `[submit-notes]` on arrival, `[admit-gate]` on a
                    // gate refusal, `[submit] accepted` on success. This one returns REJECTED with nothing
                    // logged and HTTP 200, so the wallet reports `SEND ok=True` and the money simply never
                    // moves. MEASURED 2026-08-01 on the live pair: `[submit-notes] tx carries 2306
                    // output-note byte(s) (2 whole note(s))` with `[admit-gate] 0` — the payment is built
                    // correctly and refused by no gate — while `[pool-admit]` only ever reports 1153-byte
                    // single-note cover txs. Whatever happens to the 2,306-byte payment between the gate and
                    // the pool leaves no evidence, and this is the branch that can swallow it.
                    //
                    // Per-SUBMIT and only on failure — a rare, user-driven event, never per block.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: an error KIND and a BYTE LENGTH. Never a note, cm,
                    // nullifier, amount, key, address, owner or recipient.
                    eprintln!(
                        "[submit-reject] ⛔ submit_tx_prechecked REFUSED a tx carrying {out_len} output-note \
                         byte(s): {e} — the caller is told REJECTED over HTTP 200, which the wallet reads as \
                         success, so this is a payment that silently never moves."
                    );
                    (
                        200,
                        format!(
                            "{{\"status\":\"REJECTED\",\"reason\":\"{}\"}}",
                            json_escape(&e.to_string())
                        ),
                    )
                }
            }
        }
        // /check_nullifiers_spent REMOVED (DIGITAL-CASH, user 2026-07-15). A by-nullifier "is it spent?" oracle —
        // even a bulk '0'/'1' mask — is a which-item transparency leak: an observer names nullifiers and learns
        // their spend-status + timing. Cash has NO spent-status oracle. A wallet determines its OWN notes'
        // spend-status LOCALLY/obliviously from the block stream it already relays (never asking a remote node "is
        // X spent?"). Deleted at the source, not gated — the same treatment as /register_pq_scan_key.
        ("POST", "/get_stake_tree") | ("GET", "/get_stake_tree") => {
            // The staking ECONOMICS the Earn page shows — read straight from the live ChainParams so a governance
            // retune of the APR or lock is mirrored the instant it enacts. `stake_reward_apr_bps` is the protocol's
            // governance-set TARGET reward rate (reserve-yield backed, zero-issuance); `stake_lock_blocks` is the
            // stake maturity / unbond-delay. Both are real consensus parameters, never fabricated per-user figures.
            // ⛔ `stake_root` / `stake_count` LEFT 2026-10-04 with the stake frontier: nothing fed it, and a public
            // staked-note COUNT is a volume gauge the digital-cash cardinal forbids (a staker's own position is read
            // locally by its wallet, never from the chain).
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let p = rt.node().params();
            (
                200,
                format!(
                    // #75 — NO reward-index / surplus fields (deleted counters/metadata). `stake_reward_apr_bps` is the
                    // governance POLICY rate a staker's self-minted confidential yield is bounded by.
                    "{{\"status\":\"OK\",\"stake_reward_apr_bps\":{},\"stake_lock_blocks\":{},\"target_spacing_ms\":{},\"tip_height\":{},\"stake_epoch\":{}}}",
                    p.stake_reward_apr_bps,
                    p.stake_lock_blocks,
                    p.target_spacing_ms,
                    rt.node().tip_height(),
                    // §17.6: the stake epoch of the selected tip's header (public) — the epoch a stake built now names.
                    // ⛔ TWO MEANINGS IN ONE NUMBER (§6 trap). This answered `0` BOTH for "no selected tip" AND for a tip in
                    // epoch 0 — the chain's first day after genesis, and every simulated mesh's first day (the simulator's
                    // clock starts at 0). The wallet read 0 as "no epoch yet" and refused every stake: MEASURED 2026-11-01
                    // (scratchpad/brb26/h4-pins.log, h6-pins.log) "the node named no stake epoch yet (nothing was staked)" on a
                    // funded wallet after blocks. Epoch 0 is an epoch (`ingest.rs` admits `e_now == stake_epoch_of_ms(ts)`
                    // for it like any other); "no tip" is `null`. ROOT-LAYER: this route is where the epoch is PRODUCED for
                    // the wallet; `stake_policy` only reads it. MUST-STAY-GREEN: the journeys' stake steps, F9, A5.
                    rt.node()
                        .selected_tip()
                        .and_then(|t| rt.node().dag().get(&t).map(|n| usdm_decider::whir_rec_block::stake_epoch_of_ms(n.header.timestamp)))
                        .map_or_else(|| "null".to_string(), |e| e.to_string())
                ),
            )
        }
        // ⭐ WHICH PEERS THIS NODE ACTUALLY KNOWS — the operator's own view of its own mesh.
        //
        // `peers: <count>` answered "how many" and nothing else, so a node meshed with the RIGHT network and
        // one meshed with four strangers on a dead chain read identically. Diagnosing an island then came down
        // to guessing. This is the loopback equivalent of every node software's peer listing (bitcoin-cli
        // `getpeerinfo`): the operator asking their OWN node who it is talking to.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: serves ONLY signed peer-directory records — the same bytes that are
        // already gossiped in the clear to every node on the mesh and persisted on disk, so nothing here is
        // newly disclosed. No note, amount, nullifier, address, scan key or owner appears, and the RPC binds
        // 127.0.0.1 only, so this is the node operator reading their own directory, never a remote query.
        ("GET", "/ram_census") | ("POST", "/ram_census") => {
            // ⭐⭐⭐ THE NODE ATTRIBUTES ITS OWN RESIDENT SET. Store NAMES, entry COUNTS and byte
            // estimates — the same three columns the no-growth test prints, now readable from a LIVE
            // node instead of only from a test workload. That gap is why a 300-490 MB resident set went
            // unattributed while the census totalled ~5 MB.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: store sizes only. No note, commitment, nullifier, amount,
            // key, owner or address appears, and nothing here is keyed by an item — these are the same
            // magnitudes `/get_info` already publishes as `blocks_in_memory` and `records_held`, split by
            // which store holds them. It answers "how big is this node", never "what does it hold".
            let g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let rows = g.node().ram_census_named();
            drop(g);
            let total: usize = rows.iter().map(|(_, _, b)| *b).sum();
            let items: Vec<String> = rows
                .iter()
                .map(|(n, c, b)| format!("{{\"store\":\"{n}\",\"entries\":{c},\"bytes\":{b}}}"))
                .collect();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"total_bytes\":{total},\"stores\":[{}]}}",
                    items.join(",")
                ),
            )
        }
        ("POST", "/get_peers") | ("GET", "/get_peers") => {
            let g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let peers = g.node().known_peers();
            let mut arr = String::from("[");
            for (i, p) in peers.iter().enumerate() {
                if i > 0 {
                    arr.push(',');
                }
                // The onion is the peer's DIALABLE address and is already public gossip; the key material is
                // reported by LENGTH only — a record with empty keys is silently undialable, and that is
                // exactly the failure this endpoint exists to make visible.
                arr.push_str(&format!(
                    "{{\"peer_id\":\"{}\",\"addr\":\"{}\",\"seq\":{},\"x_pk_len\":{},\"ek_len\":{},\"dialable\":{}}}",
                    p.peer_id.replace('"', ""),
                    p.addr.replace('"', ""),
                    p.seq,
                    p.x_pk.len(),
                    p.ek.len(),
                    !p.x_pk.is_empty() && !p.ek.is_empty() && p.addr.contains(".onion")
                ));
            }
            arr.push(']');
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"count\":{},\"peers\":{}}}",
                    peers.len(),
                    arr
                ),
            )
        }
        ("GET", "/get_seed_lines") | ("POST", "/get_seed_lines") => {
            // ⭐ A-F68 — THE SEED LIST A RELEASE SHIPS, FROM THE CHAIN'S OWN PEERS (docs/CHAIN-DEATH-AUDIT-20261115.md C11). Up to
            // SEED_LINES_MAX dialable peers this node knows, bonded anchors first (each cost a real bond: an eclipse needs
            // stake), then the freshest of the rest, each as the seed line a node and a wallet read
            // (`peer_id|/dns/<onion>/tcp/<port>|x_pk_hex|ek_hex`, the shape `serve` parses). A release writes them into the
            // wallet's compiled list, so a fresh install has every always-on peer as a first contact, not one machine.
            // DIGITAL-CASH-PRIVACY-REVIEWED: onion addresses and public keys, already public gossip (signed peer records);
            // no tag, amount, note or owner. SCALE: at most SEED_LINES_MAX lines whatever the directory holds (≤ MAX_PEERS).
            // BORROWED: Bitcoin Core's chainparamsseeds (a release compiles the addresses of nodes known to be up).
            const SEED_LINES_MAX: usize = 32;
            let g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (anchors, mut others) = g.node().peer_anchors();
            others.sort_by(|a, b| b.seq.cmp(&a.seq));
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            let lines: Vec<String> = anchors
                .iter()
                .chain(others.iter())
                .filter(|p| !p.x_pk.is_empty() && !p.ek.is_empty() && p.addr.contains(".onion"))
                .take(SEED_LINES_MAX)
                .map(|p| format!("\"{}|{}|{}|{}\"", p.peer_id.replace(['"', '|'], ""), p.addr.replace(['"', '|'], ""), hex(&p.x_pk), hex(&p.ek)))
                .collect();
            (200, format!("{{\"status\":\"OK\",\"anchors\":{},\"lines\":[{}]}}", anchors.len(), lines.join(",")))
        }
        ("GET", "/get_relay_faces") | ("POST", "/get_relay_faces") => {
            // ⭐ THE RELAY FACES A RELEASE SHIPS (lane af57, 2026-11-15; user: "finish pqmix to fully replace tor now"): up to
            // RELAY_FACES_MAX relay faces of our own network this node knows, its own first, each as the seed a node reads
            // (`relay:<address>:<port>`, `MONEROUSD_MIX_SEEDS` / `mix-seeds`). A release writes them into the wallet's compiled
            // list (`scratchpad/seed_list.py --relays`), so a node installed during a Tor outage still has a first contact.
            // DIGITAL-CASH-PRIVACY-REVIEWED: relay faces, public by design (docs/MONEROUSD-NATIVE-NETWORK-SPEC-20261107.md §1
            // limit 2); a hidden address is never one of them, and no tag, amount, note or owner is. SCALE: at most
            // RELAY_FACES_MAX lines whatever the view holds (≤ VIEW_MAX). BORROWED: Bitcoin Core's chainparamsseeds.
            const RELAY_FACES_MAX: usize = 32;
            let lines: Vec<String> = crate::pqmix::relay_face_addrs(RELAY_FACES_MAX).into_iter().map(|l| format!("\"{}\"", l.replace('"', ""))).collect();
            (200, format!("{{\"status\":\"OK\",\"known\":{},\"lines\":[{}]}}", lines.len(), lines.join(",")))
        }
        ("GET", "/miner_pool") | ("POST", "/miner_pool") => {
            // ⭐ §BR-11 (R7 F15) — the miner pool's open quarter and its per-block payout: the same figures every block's
            // MinerPayout object states in public. DIGITAL-CASH-PRIVACY-REVIEWED: one quarterly rate (the no-volume-leak census
            // pins that it reveals no per-block volume or timing); never the pool's balance.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.node().peg().miner_payout_rate() {
                Some((q, rate)) => (200, format!("{{\"status\":\"OK\",\"quarter\":{q},\"per_block_atomic\":{rate}}}")),
                None => (200, "{\"status\":\"OK\",\"quarter\":null,\"per_block_atomic\":0}".to_string()),
            }
        }
        ("GET", "/release_attestations") | ("POST", "/release_attestations") => {
            // ⭐ §BR-10 — the releases ≥ 3 independent builders attest (each builder's latest attestation, chain state), for
            // the wallet's update screen. DIGITAL-CASH-PRIVACY-REVIEWED: public builder signatures over public hashes.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let offered = crate::release_attestation_tx::offered_releases(rt.node().peg().release_attestations());
            let rows: Vec<String> = offered
                .iter()
                .map(|(h, ver, notes, emergency, n)| {
                    format!(
                        "{{\"release_hash\":\"{}\",\"version\":{},\"notes\":{},\"emergency\":{emergency},\"builders\":{n}}}",
                        hex_encode(h),
                        serde_json::Value::String(ver.clone()),
                        serde_json::Value::String(notes.clone())
                    )
                })
                .collect();
            (200, format!("{{\"status\":\"OK\",\"releases\":[{}]}}", rows.join(",")))
        }
        ("POST", "/release_fetch") => {
            // ⭐⭐ §BR-10 — this node's wallet wants the attested release: the node fetches every chunk it lacks from its
            // peers over the bulk lane (each verified against the attested root before it is stored) and answers how far it
            // is. DIGITAL-CASH-PRIVACY-REVIEWED: a public release root and chunk counts — no account, note or amount.
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.release_want_all() {
                Some((root, n, held)) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"root\":\"{}\",\"chunks\":{},\"held\":{held}}}",
                        hex_encode(&root),
                        n.map_or("null".to_string(), |n| n.to_string())
                    ),
                ),
                None => (200, err_json("NO_ATTESTED_RELEASE")),
            }
        }
        ("POST", "/repayment_pot") => {
            // ⭐ §BR-3 17.5 layer 1 — the repayment pot's public figures: the SAT it holds, the floor price it sells at, the USDm
            // its sales still owe the supply. DIGITAL-CASH-PRIVACY-REVIEWED: public facts of a public theft and public bonds.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (pot, floor, owed) = rt.node().repayment_pot_status();
            (200, format!(
                "{{\"status\":\"OK\",\"pot_sat\":{pot},\"floor\":{},\"scale\":{},\"owed_usdm_atomic\":{owed}}}",
                floor.map_or("null".to_string(), |f| format!("\"{f}\"")),
                crate::liquidation::PRICE_SCALE
            ))
        }
        ("POST", "/pot_buy") => {
            // ⭐ §BR-3 17.5 layer 1 — this node's wallet buys SAT from the pot at the floor (the request; custody frames it).
            let Some(b) = json_str_field(body, "request_hex").and_then(|h| hex_decode(&h)) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.pot_buy_submit(&b) {
                Ok(()) => (200, "{\"status\":\"OK\",\"relayed\":true}".to_string()),
                Err(why) => (200, format!("{{\"status\":\"REFUSED\",\"reason\":\"{why}\"}}")),
            }
        }
        ("POST", "/defi_book") => {
            // ⭐ §BR-15 — the DeFi book a wallet's Buy SAT reads: whether the pool is open, the open batch and whether it still
            // takes orders, the last clearing tick and whether the last batch expired, the roster's threshold and custody keys.
            // DIGITAL-CASH-PRIVACY-REVIEWED: the book's public fields (the separation clause's closed list: one tick per batch);
            // no order, amount or owner.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let n = rt.node();
            let pair = json_num_field(body, "pair").unwrap_or(0) as u8;
            let Some(b) = n.peg().defi_book_of(pair) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let score = n.selected_tip_blue_score().unwrap_or(0);
            let eks: Vec<String> = b.eks.iter().map(|k| format!("\"{}\"", hex_encode(k))).collect();
            // the epoch an order seals to: the one BEFORE the running epoch, whose key custody holds now (§BR-9a release) and
            // erases two epochs on — `null` in a chain's first hours (no released key yet: orders wait)
            let ek = n.peg().epoch_keys();
            let seal = ek.release_epoch().and_then(|e| ek.release_key(e).map(|pk| (e, pk)));
            let seal_json = seal.map_or("null".to_string(), |(e, pk)| {
                format!(
                    "{{\"epoch\":{e},\"b_hex\":\"{}\",\"contributors\":{}}}",
                    hex_encode(&crate::epoch_key::pack_b(&crate::epoch_key::PublicPart { b: pk.b.clone() })),
                    pk.contributors
                )
            });
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"open\":{},\"batch\":{},\"taking_orders\":{},\"slotted\":{},\"order_commits_hex\":[{}],\"closes_at\":{},\"score\":{score},\"last_tick\":{},\"last_expired\":{},\"last_sells\":{},\"income_index\":{},\"batch_index\":{},\"deposit_batch\":{},\"raise_pending\":{},\"raised\":{},\"earn_next\":{},\"t\":{},\"seal_epoch\":{seal_json},\"eks_hex\":[{}]}}",
                    b.is_open(),
                    b.batch,
                    // §18.12: an order is handed to the custody set at any time (the next batch's slots carry it), except while
                    // the custody hands the pool over
                    b.is_open() && !b.frozen(),
                    b.slotted,
                    // the slotted batch's order commitments (public chain state): how a wallet learns which batch carried its order
                    b.orders.iter().map(|o| format!("\"{}\"", hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&o.amount_commit)))).collect::<Vec<_>>().join(","),
                    b.opened_at.saturating_add(crate::defi_batch::BATCH_STEPS),
                    b.last_tick,
                    b.last_expired,
                    b.last_sells,
                    // ⭐ EARN — the pair's income index (public chain state the Earn screen values a position at) and the
                    // number of the next Earn batch, the one a withdrawal is placed for (a function of the public batch number).
                    // CACHE-ONLY: this route only reads the book, whose fields are applied from the settlement objects the
                    // blocks carry; nothing here moves a value.
                    b.income_index,
                    // ⭐ Earn step 3 — the open batch's opening index (what every order made for it must carry), whether it is
                    // the pair's deposit batch, and whether a window waits for its raise (a withdrawal waits for it)
                    b.batch_index,
                    b.deposits,
                    b.closed > b.raised,
                    b.raised,
                    b.batch + (crate::defi_earn::EARN_EVERY - 1 - b.batch % crate::defi_earn::EARN_EVERY),
                    b.t,
                    eks.join(",")
                ),
            )
        }
        ("POST", "/defi_prices") => {
            // ⭐ §18.15 — a pair's price history for the wallet's chart: each resolution's `[seconds, tick]` points and the live tick.
            // DIGITAL-CASH-PRIVACY-REVIEWED: the closed list's one price per batch and block times, public chain state; no volume, depth, order or owner.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let pair = json_num_field(body, "pair").unwrap_or(0) as u8;
            let Some(b) = rt.node().peg().defi_book_of(pair) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let rings: Vec<String> = b
                .prices
                .levels
                .iter()
                .map(|ring| format!("[{}]", ring.iter().map(|(s, t)| format!("[{s},{t}]")).collect::<Vec<_>>().join(",")))
                .collect();
            (200, format!("{{\"status\":\"OK\",\"pair\":{pair},\"last_tick\":{},\"levels\":[{}]}}", b.last_tick, rings.join(",")))
        }
        ("POST", "/submit_defi_order") | ("POST", "/submit_defi_claim") => {
            // ⭐ §BR-15 §18.12 — this node's wallet's order slot (Buy SAT) or claim slot: checked statelessly here (the order's
            // share proof needs the book's threshold), then handed to the custody lane, which gossips it to the custody set;
            // it reaches the chain only inside its batch's `DefiSlots`, beside covers, so no block shows a count.
            // DIGITAL-CASH-PRIVACY-REVIEWED: the slot is commitments, a nullifier, proofs and sealed shares — what the chain
            // would carry anyway; relayed, never stored or logged here.
            let Some(bytes) = json_str_field(body, "object_hex").and_then(|h| hex_decode(&h)) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let claim = path == "/submit_defi_claim";
            let mut pair = 0u8;
            let why = if claim {
                match crate::defi_batch::DefiClaimTx::decode(&bytes) {
                    Some(t) => {
                        pair = t.pair;
                        t.self_valid()
                    }
                    None => Some("a malformed claim"),
                }
            } else {
                let t = rt.node().peg().defi_book().t;
                match crate::defi_batch::DefiOrderTx::decode(&bytes) {
                    Some(o) => {
                        pair = o.pair;
                        o.self_valid(t)
                    }
                    None => Some("a malformed order"),
                }
            };
            match why {
                Some(why) => (200, format!("{{\"status\":\"REFUSED\",\"reason\":\"{}\"}}", why.replace('"', "'"))),
                None if rt.node_mut().push_defi_intake(pair, claim, bytes) => (200, "{\"status\":\"OK\",\"verdict\":\"HANDED_TO_CUSTODY\"}".to_string()),
                None => (200, "{\"status\":\"REFUSED\",\"reason\":\"the custody hand-off is full — try again in a moment\"}".to_string()),
            }
        }
        ("POST", "/defi_fill") => {
            // ⭐ §BR-15 — where this node's wallet's order filled, when it missed its batch's outcome: the refund leaf or the buy
            // leaf at a tick, among the notes this node's held records name. DIGITAL-CASH-PRIVACY-REVIEWED: answered to this
            // node's own wallet over loopback; nothing is stored or gossiped.
            let lanes = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b));
            let (Some(ac), Some(lc)) = (lanes("amount_commit_hex"), lanes("limit_commit_hex")) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let hint = json_str_field(body, "tick").and_then(|s| s.parse::<i64>().ok());
            // ⭐ EARN — an Earn batch's leaf and a deposit batch's leaf say so in their lanes; no leaf names an index (the order
            // carries its own). DIGITAL-CASH-PRIVACY-REVIEWED: as above.
            let held = {
                let g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node().held_note_cms()
            };
            match crate::defi_batch::find_fill_x(&held, &ac, &lc, hint) {
                Some((None, _, _)) => (200, "{\"status\":\"OK\",\"refund\":true}".to_string()),
                Some((Some((t, j, sells)), earn, dep)) => {
                    (200, format!("{{\"status\":\"OK\",\"refund\":false,\"tick\":{t},\"j_min\":{j},\"sells\":{sells},\"earn\":{earn},\"dep\":{dep}}}"))
                }
                None => (200, "{\"status\":\"NOT_YET\"}".to_string()),
            }
        }
        ("POST", "/unit_book") => {
            // ⭐ §BR-4 — the public unit book a wallet dates its unit by: the day at this node's tip, each band's epoch, each
            // band's floor price word, and each cell's open count (all public by design, docs/BR-4-7 §10.3).
            // DIGITAL-CASH-PRIVACY-REVIEWED: public counts and words; no owner, note or amount of anyone's.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let n = rt.node();
            let book = n.peg().unit_book();
            let floors: Vec<String> = (0..crate::debt_units::BANDS).map(|k| format!("\"{}\"", crate::debt_units::band_price_word(k))).collect();
            let price = n.peg().reference_price(crate::peg::NATIVE_PEG_ASSET_ID).map_or("null".to_string(), |p| format!("\"{p}\""));
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"day\":{},\"band_epochs\":{:?},\"open\":{:?},\"floors\":[{}],\"reference_price\":{price},\"scale\":{},\"unit_atomic\":{:?},\"rate_bps\":{}}}",
                    n.unit_day_now(),
                    book.band_epoch,
                    book.open,
                    floors.join(","),
                    crate::liquidation::PRICE_SCALE,
                    crate::debt_units::UNIT_ATOMIC,
                    crate::debt_units::UNIT_RATE_BPS
                ),
            )
        }
        ("POST", "/unit_close") => {
            // ⭐ §BR-4 B4-3 — this node's wallet closes one debt unit (the request; custody frames it).
            let Some(b) = json_str_field(body, "request_hex").and_then(|h| hex_decode(&h)) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.unit_close_submit(&b) {
                Ok(()) => (200, "{\"status\":\"OK\",\"relayed\":true}".to_string()),
                Err(why) => (200, format!("{{\"status\":\"REFUSED\",\"reason\":\"{why}\"}}")),
            }
        }
        ("POST", "/mix_rounds") => {
            // ⭐⭐ §BR-6 — the current epoch's entry-mix round views this node holds (each the designated coordinator's signed
            // view; the wallet decodes and verifies them with `entry_mix::RoundView::decode` and derives every round id itself).
            // DIGITAL-CASH-PRIVACY-REVIEWED: public round state every node relays — credential commitments and a transaction
            // Bitcoin will publish; nothing names which input pays which output.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let views: Vec<String> = rt.mix_views().iter().map(|v| format!("\"{}\"", hex_encode(v))).collect();
            (200, format!("{{\"status\":\"OK\",\"now_ms\":{},\"views\":[{}]}}", rt.now_unix_ms(), views.join(",")))
        }
        ("POST", "/mix_send") => {
            // ⭐⭐ §BR-6 — one registration (input, output or signature) from this node's wallet, sent point to point to the
            // round's coordinator on a FRESH Tor circuit. Answers the request hash its verdict will carry (`/mix_answer`).
            // DIGITAL-CASH-PRIVACY-REVIEWED: the wallet's own registration to its own node; nothing is logged.
            let Some(req) = json_str_field(body, "request_hex").and_then(|h| hex_decode(&h)) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.mix_send(&req) {
                Ok(h) => (200, format!("{{\"status\":\"OK\",\"request\":\"{}\"}}", hex_encode(&h))),
                Err(why) => (200, format!("{{\"status\":\"NOT_SENT\",\"reason\":\"{why}\"}}")),
            }
        }
        ("POST", "/mix_answer") => {
            // §BR-6 — the coordinator's verdict on one of this wallet's registrations, once its answer arrived.
            let Some(h) = json_str_field(body, "request").and_then(|h| hex_decode(&h)).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.mix_answer(&h) {
                Some(Ok(())) => (200, "{\"status\":\"OK\",\"accepted\":true}".to_string()),
                Some(Err(why)) => (200, format!("{{\"status\":\"OK\",\"accepted\":false,\"reason\":\"{}\"}}", why.replace('"', "'"))),
                None => (200, err_json("NOT_YET")),
            }
        }
        ("POST", "/release_chunk") => {
            // §BR-10 — one stored chunk of the held release, for this node's wallet to assemble (it re-verifies the whole
            // file against the attested root). DIGITAL-CASH-PRIVACY-REVIEWED: public release bytes.
            let Some(i) = json_num_field(body, "index").and_then(|i| u32::try_from(i).ok()) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.release_chunk(i) {
                Some(c) => (200, format!("{{\"status\":\"OK\",\"index\":{i},\"chunk_hex\":\"{}\"}}", hex_encode(&c))),
                None => (200, err_json("NOT_HELD_YET")),
            }
        }
        ("POST", "/submit_release_attestation") => {
            // ⭐ §BR-10 — a builder posts its signed attestation; every node records it at the fold.
            // CHAIN-PUBLISH-REVIEWED: `publish_release_attestation` admits the framed object as a transaction.
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| crate::release_attestation_tx::ReleaseAttestationTx::decode(&b));
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_RELEASE_ATTESTATION"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_release_attestation(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (200, "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\"}".to_string()),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"RELEASE_ATTESTATION_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("GET", "/get_rule_set") | ("POST", "/get_rule_set") => {
            // ⭐ §BR-10 — the rule set this node enforces: its id (`deployment::rule_set_id` over the chain id and every active
            // deployment) and each deployment's state, so a wallet shows signalling status and two nodes compare rule sets.
            // DIGITAL-CASH-PRIVACY-REVIEWED: public consensus state (block versions and validator signals), no note or amount.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let chain_id = rt.node().dag().genesis().map(|g| hex_encode(g.as_bytes())).unwrap_or_else(|| "nogenesis".to_string());
            let ledger = rt.node().peg().deployments();
            let id = crate::deployment::rule_set_id(&chain_id, ledger);
            let rows: Vec<String> = ledger
                .table()
                .iter()
                .map(|d| format!("{{\"name\":\"{}\",\"bit\":{},\"state\":\"{:?}\"}}", d.name, d.bit, ledger.state(d.name)))
                .collect();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"rule_set_id\":\"{}\",\"update_needed\":{},\"deployments\":[{}]}}",
                    hex_encode(&id),
                    ledger.update_needed,
                    rows.join(",")
                ),
            )
        }
        // ⭐ SPEED R5 (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §3; L3 of docs/CHAIN-SPEED-SPEC-20261109.md) — THE POOL'S NOTE
        // PAGE: every output note of every payment this node's pool holds, whole, in pool order. A wallet tries each
        // note with its own key, locally, and shows a payment to it as "incoming, settling" seconds after it was sent,
        // instead of after its block is proved and folded.
        // ROOT-LAYER: the one read of pooled notes a wallet makes; the pool door (`ingest_tx`) is where a payment's own
        //   proofs were verified, so a note is on this page only if its payment passed that door.
        // MEASURED: real nodes 2026-11-09/10 — a payment reaches the other node's pool about 5 s after it is sent
        //   (`[tx-origin]` echo 5,162 ms) and was spendable there 88-262 s later; the payee saw nothing in between.
        // DIGITAL-CASH-PRIVACY-REVIEWED: the WHOLE page, every time — no which-note, which-address or which-amount
        //   question exists on this route, and its content is a function of the pool alone (cover payments' notes
        //   included, indistinguishable from real ones), never of who asks. The same bytes are already relayed to every
        //   peer with the payment. Nothing is decrypted here: the scan key never leaves the wallet.
        // §9.6: a READ, no ingress — nothing enters the pool, a block or the fold through it. Bounded work: one pass over
        //   the pool, whose size is the pool's own bound; nothing is kept.
        // cons: one loopback answer of about 0.3-0.6 MB of hex per wallet refresh (the pool's 256 cover payments plus the
        //   real ones); 0 B on the chain or the mesh.
        ("GET", "/pool_notes") => {
            let r = rt.lock().unwrap_or_else(|e| e.into_inner());
            let mut page = String::new();
            let mut notes = 0usize;
            // Payment locks (spec §11 stage 1): beside every note, how much finality stake has locked the payment that
            // carries it, in basis points. The same figure for every note on the page, asked for by no one in particular.
            // DIGITAL-CASH-PRIVACY-REVIEWED: one number per pool note, derived from signatures every relaying node holds;
            // the page is the whole pool, so the request names no note and no owner.
            let mut locked = String::new();
            for tx in r.node().mempool().iter() {
                let bp = r.node().lock_weight_bp_of_tx(tx);
                for note in tx.output_notes.chunks_exact(crate::cover::PQ_NOTE_BYTES) {
                    page.push_str(&hex_encode(note));
                    if notes > 0 {
                        locked.push(',');
                    }
                    locked.push_str(&bp.to_string());
                    notes += 1;
                }
            }
            // What this node's lock door did since it started, by kind: counted, kept early, duplicate, refused (shape,
            // expired, no stake, another lifetime, signature), counted from early, dropped for its lifetime, gave way.
            // DIGITAL-CASH-PRIVACY-REVIEWED: eleven totals over lock messages every relaying node receives; no
            // statement, key, note or owner, and nothing a peer could not count from the same gossip.
            let door = r.node().lock_door_tally().iter().map(u64::to_string).collect::<Vec<_>>().join(",");
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"notes\":{notes},\"note_bytes\":{},\"locked_bp\":[{locked}],\"lock_door\":[{door}],\"page_hex\":\"{page}\"}}",
                    crate::cover::PQ_NOTE_BYTES
                ),
            )
        }
        ("GET", "/get_info") => {
            // ⭐ PROOF-OF-LIFE MUST NEVER BLOCK (user 2026-08-25: the wallet UI flashed "Starting your
            // node…" and reset the balance card whenever a status probe landed during adopt/heal work).
            // The probe's question is "is the node alive and roughly where" — it must not queue behind
            // multi-hundred-ms lock holders. On contention, serve the LAST SUCCESSFUL full response
            // (same serializer, one representation, at most seconds old); the next uncontended poll
            // refreshes it. A cold process with no cache yet answers a minimal OK (alive, warming).
            // DB-137: the producer-side refresher (its thread is marked) WAITS for the lock; a request never does.
            let acquired = if INFO_REFRESH_BLOCKING.with(|f| f.get()) {
                rt.lock().map_err(std::sync::TryLockError::Poisoned)
            } else {
                rt.try_lock()
            };
            let mut rt = match acquired {
                Ok(g) => g,
                Err(std::sync::TryLockError::WouldBlock) => {
                    let c = get_info_cache().lock().unwrap_or_else(|e| e.into_inner());
                    if c.is_empty() {
                        // ⛔ NOT `busy:true` AND NOTHING ELSE — that answer took 103 SECONDS to become
                        // useful on a freshly launched node (see `publish_live_status`). The height is
                        // published lock-free by the runtime, so it is available on the very first poll.
                        return (200, busy_info_json());
                    }
                    return (200, c.clone());
                }
                Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            };
            // Join-mesh-or-nothing state, mirrored to the UI: false = this node has not yet adopted/grafted
            // from any live peer, so its production is gated and its height will not climb locally.
            let mesh_joined = rt.mesh_joined();
            // …and HOW it joined (DB-135b): a live graft, a bundle adopt, the resume rule or the operator
            // directive read differently to an operator, and the flag alone cannot tell them apart.
            let mesh_joined_how = rt.mesh_joined_how();
            // ⛔ PUBLISH FOREIGN-NETWORK CONTACTS. `mesh_joined` alone is not honesty: it is set by
            // MONEROUSD_MESH_BOOTSTRAP=1, i.e. "this node declared itself an origin", NOT "this node is
            // connected to anyone". A node rejecting every peer as a different network reported
            // `mesh_joined: true` and looked perfectly healthy. This number makes that state self-evident.
            let foreign_network_contacts = rt.foreign_network_contacts();
            // ⛔ HOW MANY PEERS THIS NODE ACTUALLY KNOWS. `/get_info` published no peer count at all, so a node
            // with zero peers and a fully-meshed one were byte-identical to every reader — which is how an
            // island stayed invisible for weeks, to the user AND to me. `mesh_joined` does not answer this: it
            // is set by MONEROUSD_MESH_BOOTSTRAP, i.e. "I declared myself an origin", not "I am connected".
            let peer_count = rt.node().known_peers().len();
            // ⛔ A DIRECTORY ENTRY IS NOT A LIVE LINK. `peers` counts who we know how to dial; a node can be
            // exchanging and adopting (`[dsync] SyncResponse -> Adopted`) with an EMPTY directory, so `peers 0`
            // sat next to a plainly working link and a good settle run was written off as "unpeered".
            // Report the live signal alongside it. DIGITAL-CASH-PRIVACY-REVIEWED: a message COUNT only — the
            // same class of chain-progress figure /get_info already serves. No note, amount, key or owner.
            let live_contacts = rt.live_peer_contacts();
            // ⛔⛔⛔ `live_peer_contacts` IS CUMULATIVE — IT CANNOT REPORT A LINK THAT DIED.
            //
            // It only ever increments, so once one message has ever arrived it reads non-zero forever and
            // holds the SAME value on a healthy link and on a link that delivered for hours and then dropped.
            // Every readiness check built on it inherits that: the send-precondition gate's `inbound > 0` test
            // can never fail again after the first message, for the life of the process.
            //
            // MEASURED 2026-08-09: `27840 peers=2 writers_held=0 inbound=9132563`. Nine million inbound
            // beside zero writers — dead, and called alive by every consumer of the total.
            //
            // Publish the DELTA beside it so one RPC sample separates history from liveness.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a message COUNT of the same class `live_peer_contacts` already
            // publishes. Names no peer, address, note, amount, key or owner.
            let live_contacts_delta = rt.live_peer_contacts_delta();
            // Outbound links this node HOLDS, published beside the inbound count. `live_peer_contacts` alone
            // cannot distinguish "nobody can reach me" from "nobody is dialling me", and that ambiguity cost
            // several turns of theorising on 2026-08-01 (node A read live=0 all session while B read
            // thousands). With both numbers a refusal says WHICH side is at fault, from the RPC, without
            // reading either node's log.
            let writers_held = rt.live_writers_held();
            let onion_pub = rt.onion_published();
            // THIS node's own dialable address, published so an address MISMATCH is one RPC call instead of
            // log archaeology.
            //
            // MEASURED 2026-08-01: node B was dialing `uyqkj5sf....onion` while node A was actually serving
            // `vl52qoaix....onion` — a stale seed pointing at an address that no longer resolves. Nothing in
            // `get_info` exposed either address, so the mismatch was only visible by grepping both nodes' logs
            // and comparing by eye, and the pair read as a mysterious `inbound 0` on both sides for the whole
            // session. With both nodes publishing their own address, "B is dialing the wrong A" is immediate.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: this node's OWN onion — the address it already gossips to every
            // peer and prints in its seed line, and the one thing a peer must know to reach it. Names no other
            // peer, no note, amount, key or owner.
            let own_addr = rt
                .own_peer_record()
                .map(|r| r.addr.clone())
                .unwrap_or_default();
            let resp = match rt.rpc(RpcRequest::GetInfo) {
                RpcResponse::Info(i) => {
                    // CHAIN FINGERPRINT: a one-way blake3 digest of the genesis commitment. It changes iff the
                    // chain's genesis changes — i.e. a FRESH genesis is a genuinely DIFFERENT chain (mainnet-parity:
                    // a re-genesis is a new chain with its own funding, not a continuation). A wallet compares this
                    // across sessions so it treats a new chain as a clean slate (never shows another chain's
                    // history). Reveals nothing — it is a digest, not the commitment.
                    // CHAIN IDENTITY = THE GENESIS BLOCK ID. It was derived from a per-NETWORK commit, which
                    // is the same value for every chain that network ever has — so a re-genesis reported the
                    // identical id, and every wallet scoped to it (note store, swap log, scan state) carried
                    // notes forward onto a chain those notes were never in. The wallet then showed a balance it
                    // could not spend and EVERY send failed the anchor gate, because the note's anchor only
                    // existed on the wiped chain. The genesis id is the true identity: same for all peers of one
                    // chain, different the moment genesis differs, so stale state cannot survive by construction.
                    let chain_id = rt
                        .node()
                        .dag()
                        .genesis()
                        .map(|g| hex_encode(g.as_bytes()))
                        .unwrap_or_else(|| "nogenesis".to_string());
                    // NOVEL PRIVATE EXPLORER METRICS — derived ONLY from replicated chain PARAMETERS, never from observed
                    // volume, so they leak zero digital-cash metadata (DIGITAL-CASH-PRIVACY-REVIEWED: tx_per_block is
                    // the CONSTANT 256 cover shape [BLOCK_FIXED_TX_COUNT], identical for every block regardless of how
                    // many real spends it carries; tps + proving_power are pure functions of dag_width / target
                    // spacing / required_stamp_bits — the same numbers whether the chain is idle or saturated).
                    //   tx_per_block  = 256 (the fixed cover count every block wears)
                    //   tps           = tx_per_block × blocks-per-second, blocks/s = dag_width / spacing
                    //   proving_power = network PoUW work rate = dag_width × 2^required_stamp_bits / spacing (proof-hashes/s)
                    let txpb = crate::cover::BLOCK_FIXED_TX_COUNT as u64;
                    let spacing_ms = i.params.target_spacing_ms.max(1);
                    let width = i.params.dag_width as u64;
                    let tps = txpb.saturating_mul(width).saturating_mul(1000) / spacing_ms;
                    let work_per_block = 1u64
                        .checked_shl(i.required_stamp_bits.min(63))
                        .unwrap_or(u64::MAX);
                    let proving_power =
                        work_per_block.saturating_mul(width).saturating_mul(1000) / spacing_ms;
                    // The NOTE-STREAM position: how many records the served stream holds. This is the index
                    // `/get_my_pq_notes` pages by, and it is NOT the chain height — every note record made
                    // outside block production (testnet issuance, peg-in, reward, bond return) advances it
                    // without advancing height. A wallet that seeds its scan cursor from `height` therefore
                    // drifts from the very stream it is reading, and its self-built membership witness — which
                    // aligns to the LEAF count, i.e. this index — silently stops matching, so spends fail with
                    // an unbuildable copath. Wallets must seed from THIS.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a position in the constant-256 cover stream, not a count of
                    // real notes — it advances identically whether every block is idle or full, so it discloses
                    // no volume, no amount, and nothing about any individual note.
                    let served_seq = rt.node().served_block_count();
                    // PRODUCE-CADENCE PROBE fields + the tip's DAA work value — the discriminating
                    // signals for a slow live cadence (lock wait vs grind vs graft vs work level),
                    // published so the diagnosis is ONE RPC read. Privacy: durations, counts and the
                    // consensus-public header `work` — the same chain-progress class as blue_score.
                    let pp_lock_wait = crate::node_runtime::PRODUCE_LOCK_WAIT_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let pp_grind = crate::node_runtime::PRODUCE_GRIND_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let pp_cycle = crate::node_runtime::PRODUCE_CYCLE_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let pp_blocks = crate::node_runtime::PRODUCE_BLOCKS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let pp_fails = crate::node_runtime::PRODUCE_MINE_FAILS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let tick_passes =
                        crate::node_runtime::TICK_PASSES.load(std::sync::atomic::Ordering::Relaxed);
                    let tick_last_ms = crate::node_runtime::TICK_LAST_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let tick_blocks = crate::node_runtime::TICK_PRODUCE_BLOCKS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ip_att = crate::node_runtime::INLINE_PRODUCE_ATTEMPTS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ip_tmpl = crate::node_runtime::INLINE_TEMPLATE_NONE
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ip_mine = crate::node_runtime::INLINE_MINE_NONE
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ip_graft = crate::node_runtime::INLINE_GRAFT_NONE
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let bp_slots =
                        crate::node_runtime::BEGIN_SLOTS.load(std::sync::atomic::Ordering::Relaxed);
                    let bp_jobs =
                        crate::node_runtime::BEGIN_JOBS.load(std::sync::atomic::Ordering::Relaxed);
                    let bp_tmpl_none = crate::node_runtime::BEGIN_TEMPLATE_NONE
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let tmpl_ms =
                        crate::node_runtime::TEMPLATE_MS.load(std::sync::atomic::Ordering::Relaxed);
                    let graft_ms =
                        crate::node_runtime::GRAFT_MS.load(std::sync::atomic::Ordering::Relaxed);
                    let g_relay = crate::node_runtime::GRAFT_RELAY_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let g_uns = crate::node_runtime::GRAFT_UNSPENT_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let g_rec = crate::node_runtime::GRAFT_RECORD_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let g_bond = crate::node_runtime::GRAFT_BOND_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ing_blocks =
                        crate::node_runtime::ING_BLOCKS.load(std::sync::atomic::Ordering::Relaxed);
                    let ing_verify = crate::node_runtime::ING_VERIFY_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ing_graft = crate::node_runtime::ING_GRAFT_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ing_apply = crate::node_runtime::ING_APPLY_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let ing_save =
                        crate::node_runtime::ING_SAVE_MS.load(std::sync::atomic::Ordering::Relaxed);
                    let ing_pow =
                        crate::node_runtime::ING_POW_MS.load(std::sync::atomic::Ordering::Relaxed);
                    let ing_settle = crate::node_runtime::ING_SETTLE_MS
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let tip_work = rt
                        .node()
                        .selected_tip()
                        .and_then(|t| rt.node().dag().get(&t).map(|n| n.header.work))
                        .unwrap_or(0);
                    // ⛔ THE ROLL GATE MUST MEASURE RECORD COMPLETENESS, NOT AN APPEND CURSOR. served_seq
                    // parity between two nodes says both APPEND at the same rate — it says NOTHING about
                    // whether either holds the history. MEASURED 2026-08-13: a rolling restart gated on
                    // served_seq parity rolled the second node while the first held ~0 old records; both
                    // then served 6,723 loud no-vouch answers and the history reached zero live copies.
                    // records_held == record_top is the honest roll-safe signal: this node can vouch for
                    // its entire ordinal space. Two integer reads — no walk, no growth.
                    let records_held = rt.node().da_records_held();
                    let record_top = rt.node().da_record_ordinal_top();
                    // The count comparison was the wrong source (the ordinal counter is not dense —
                    // MEASURED: top 15406 vs held 1434 on a healthy origin, False forever). The REPLAY
                    // verdict is the truth: READY ⇔ the whole spend history replays from local records.
                    let history_complete = rt.node().serve_ready();
                    // ⛔⛔⛔ THE ROLL GATE'S TRUTH. `history_complete` latches TRUE on a node that healed to its
                    // OWN view, so it is only meaningful beside root equality; `missing_records` is the
                    // hole count a rolling restart must see at ZERO on the first node before the second is
                    // stopped — run 27 (2026-09-02) killed n2 while n1 was holed at matched_ord=66 because
                    // the gate compared the ADOPTED unspent_root alone, and both sides ended mutually holed.
                    let unspent_serve_ready = rt.node().serve_ready();
                    let wanted_records = rt.node().has_wanted_records();
                    let wanted_ids = rt.node().has_wanted_record_ids();
                    let missing_records = rt.node().missing_record_count();
                    // ⭐ 2026-09-06: `missing_records` is RANGE-DERIVED (by-id byte wants + spend-fold
                    // gaps + the certified-position-minus-cursor backlog, node.rs
                    // `missing_record_count`) — the by-ORDINAL request lists no longer feed it, so it
                    // states the true debt size at any scale instead of saturating at the slot cap.
                    // The history below is why the split fields beside it exist and stay.
                    // ⛔⛔⛔ `missing_records` AT THE CAP IS A SATURATED BOUND, NOT A DEBT SIZE — AND THE
                    // ROLL GATE READS IT AS A MAGNITUDE. (Historical: the capped-list era, closed above.)
                    //
                    // MEASURED 2026-09-05, ecosystem gate step 3 (scratch /tmp/musd-ecocheck-D6U9H2):
                    // BOTH nodes reported `missing_records` = exactly 33 on every one of ~100 polls
                    // across ~7 minutes and it never moved once. 33 was never 33 debts: `da_wanted_ids`
                    // is refused at TX_REQ_FIXED_COUNT (32) at every insert site (node.rs), so the set
                    // PINS at 32 while further wants are turned away at the door — n2 registered 136
                    // distinct copath wants that run and 104 of them never entered the set at all. A
                    // reader seeing 33 cannot tell "32 wants, filling" from "the want set is FULL and
                    // refusing", and those two need opposite actions (wait vs re-anchor).
                    //
                    // ROOT-LAYER: the count is a SUM of five producer-owned want sets
                    // (`missing_record_breakdown`, node.rs — the same producer `/record_holding` reads)
                    // and the cap binds those sets INDIVIDUALLY, so their sum can never express
                    // saturation. Serving the five addends beside the cap constant makes saturation a
                    // READ instead of an inference; this adds no second producer and computes no second
                    // opinion — every field is an O(1) `len()` of a set the node already maintains.
                    // MEASURED: 33 pinned for ~7 min on both nodes; cap = TX_REQ_FIXED_COUNT = 32; 136
                    // wants registered vs 32 admitted on the peer.
                    // MUST-STAY-GREEN: `get_info_route_returns_live_json` (the roll-gate field pin), the
                    // rpc_http route-table sweep, and `/record_holding`'s split — same producer counts,
                    // unchanged.
                    //
                    // PRIVACY, stated rather than asserted: every field added here is a COUNT of this
                    // node's own want sets, plus a compile-time protocol constant and a boolean derived
                    // from those counts. No record id, ordinal, cm, note, amount, key, address or owner
                    // is served — the ids themselves stay off the wire deliberately, the same way the
                    // by-id ask's log line keeps them off the log. The counts are answered identically
                    // to every caller (no selector, no per-asker shape), so they cannot become a
                    // which-item question about who owns what.
                    let (mw_ord, mw_rid, mw_da_id, mw_da_ord, mw_gap) =
                        rt.node().missing_record_breakdown();
                    let missing_want_cap = crate::protocol::TX_REQ_FIXED_COUNT;
                    // TRUE when ANY capped want set is full: further wants of that class are being
                    // refused at the door, so the served count is a FLOOR on the real debt, not the
                    // debt. (`uns_spendfold_gap` is uncapped and is deliberately not part of this test.)
                    let missing_wants_saturated = mw_ord >= missing_want_cap
                        || mw_rid >= missing_want_cap
                        || mw_da_id >= missing_want_cap
                        || mw_da_ord >= missing_want_cap;
                    // Unapplied payload blocks. A node draining these is NOT ready to vouch for its root: its
                    // live root lags every block it has not yet applied (measured 2026-09-03: ready Y/Y,
                    // missing 0/0, roots DIFFER by 150–200 heights — the peer had applied 78 of 894).
                    let note_payload_debt = rt.node().note_payload_debt();
                    // READY := present_complete && sidecar_gap_count()==0 — the fold-space hole count,
                    // RANGE-derived since 2026-09-06 (spend-fold gaps + the certified-position-minus-
                    // cursor backlog; the fixed-slot request lists no longer feed the verdict, so a
                    // healed node's gap actually reaches 0). `note_payload_debt` above is
                    // the DAS byte backlog: reported, never a readiness term (a jumped node at any real
                    // block rate over Tor never drains it, and does not need to — any holder serves bytes).
                    let sidecar_gap_count = rt.node().sidecar_gap_count();
                    // ⭐⭐⭐ FOLD LIVENESS — WITHOUT THESE, A DEAD CHAIN AND A LIVE ONE ARE BYTE-IDENTICAL.
                    //
                    // MEASURED 2026-09-24: both live nodes had been frozen for ~2.5 days and this door
                    // answered `200 OK` with a constant `height` the whole time. `height` is the DAG TIP,
                    // which stays perfectly current on a node whose FOLD is wedged — so the one number a
                    // reader looks at was the one number that was fine. The fold's backlog (97,706) and
                    // the id it was stuck on existed only inside a sampled log line on one node.
                    //
                    // LIVENESS IS NOT HEIGHT, IT IS HEIGHT MOVING, and the same holds for the fold: a
                    // backlog alone can be ordinary catch-up. `fold_wedged` is the DECISION
                    // (`Node::fold_wait_is_unrecoverable`), published so an operator, the wallet and the
                    // ecosystem gate read the same verdict instead of three guesses at it.
                    //
                    // DIGITAL-CASH-PRIVACY-REVIEWED: two chain-shape counts and a boolean — the same class
                    // of figure this door already serves (blue_score, records_held, sidecar_gap_count).
                    // Never a tag, note, amount, key, owner or ordering.
                    // ⭐ LANE-A SERVEABILITY. Measured 2026-09-24: /get_nf_copath answered 503 on BOTH
                    // live nodes for a random never-spent tag while the drift alarm had fired zero times,
                    // because that alarm cannot fire on a treeless node or one whose fold has stopped.
                    // Published so "this node cannot prove anything unspent" is a fact a reader can see.
                    let (nf_view_present, nf_view_matches_acc) = rt.node().nf_copath_source_state();
                    // ⭐ THE RECORD-SIDE STALL. `missing_records` already says HOW MANY are wanted; it
                    // cannot say that the SAME ones have been wanted unchanged for ~27,000 sweeps, which
                    // is the difference between a node catching up and a node that never will.
                    let record_want_stall_passes = rt.node().da_want_stall_passes();
                    // ⭐ AND THE SAME STALL IN SECONDS, because a PASS COUNT IS NOT A BOUND: sweeps happen
                    // per tick, so the identical physical stall reads differently on a fast machine, a
                    // loaded one, or a node whose drain is slow — exactly the population this measures.
                    let record_want_stall_ms = rt.node().da_want_stall_ms();
                    let fold_unfolded = rt.node().unfolded_blocks_len();
                    let fold_wait_passes = rt.node().fold_wait_state().map(|(_, k)| k).unwrap_or(0);
                    // ONE question, one answer: the door, the runtime's escalation and the ecosystem gate
                    // all read the same verdict, so they cannot disagree about whether this node is stuck.
                    let fold_wedged = rt.node().wedge_reason().is_some();
                    // Blocks folded into A_tip. It MUST equal the number of absence-fold records served, or a
                    // spender's fold can never reproduce A_tip and every send fails closed.
                    let nf_fold_seq = rt.node().nf_fold_seq();
                    (
                        200,
                        // `height` == blue_score is the CANONICAL GHOSTDAG chain height (same convention as
                        // /get_height), exposed here so every /get_info consumer reads the true height under the
                        // conventional field name. `blocks` (= n_blocks, the in-memory DAG node count) is small
                        // after an O(1) #106 frontier-persist restart and is NOT the chain height — never display it.
                        // DIGITAL-CASH PRIVACY: /get_info serves ONLY chain-progress + anti-spam difficulty +
                        // PARAM-DERIVED cover-rate metrics — NEVER an observed volume/supply/count figure.
                        // `mempool_txs`/`mempool_weight` (pending-tx COUNT + VOLUME) are DELIBERATELY absent: a private
                        // DAG must leak zero throughput/volume metadata to an observer (an adaptive `required_stamp_bits`
                        // already carries the only congestion signal the wallet needs to size its anti-spam PoW).
                        format!(
                            "{{\"status\":\"OK\",\"blocks\":{},\"blocks_in_memory\":{},\"tips\":{},\"blue_score\":{},\"height\":{},\"finalized_height\":{},\"required_stamp_bits\":{},\"dag_width\":{},\"target_spacing_ms\":{},\"sat_halving_interval\":{},\"tx_per_block\":{},\"tps\":{},\"proving_power\":{},\"chain_id\":\"{}\",\"mesh_joined\":{},\"mesh_joined_how\":\"{}\",\"foreign_network_contacts\":{},\"network_id\":\"{}\",\"build_unix\":{},\"build_time\":\"{}\",\"build_src\":\"{}\",\"peers\":{},\"live_peer_contacts\":{},\"live_peer_contacts_delta\":{},\"live_writers_held\":{},\"onion_published\":{},\"own_addr\":\"{}\",\"served_seq\":{},\"records_held\":{},\"record_top\":{},\"final_record_top\":{},\"history_complete\":{},\"nf_fold_seq\":{},\"account_root\":\"{}\",\"token_registry_root\":\"{}\",\"membership_acc\":\"{}\",\"unspent_root\":\"{}\",\"produce_lock_wait_ms\":{},\"produce_grind_ms\":{},\"produce_cycle_ms\":{},\"produce_blocks\":{},\"produce_mine_fails\":{},\"tip_work\":{},\"tick_passes\":{},\"tick_last_ms\":{},\"tick_blocks\":{},\"ip_attempts\":{},\"ip_template_none\":{},\"ip_mine_none\":{},\"ip_graft_none\":{},\"bp_slots\":{},\"bp_jobs\":{},\"bp_template_none\":{},\"template_ms\":{},\"graft_ms\":{},\"graft_relay_ms\":{},\"graft_unspent_ms\":{},\"graft_record_ms\":{},\"graft_bond_ms\":{},\"ing_blocks\":{},\"ing_verify_ms\":{},\"ing_graft_ms\":{},\"ing_apply_ms\":{},\"ing_save_ms\":{},\"ing_pow_ms\":{},\"ing_settle_ms\":{},\"unspent_serve_ready\":{},\"wanted_records\":{},\"wanted_ids\":{},\"missing_records\":{},\"missing_by_ordinal\":{},\"missing_by_record_id\":{},\"missing_da_by_id\":{},\"missing_da_by_ordinal\":{},\"missing_spendfold_gap\":{},\"missing_want_cap\":{},\"missing_wants_saturated\":{},\"note_payload_debt\":{},\"sidecar_gap_count\":{},\"fold_unfolded\":{},\"fold_wait_passes\":{},\"fold_wedged\":{},\"nf_view_present\":{},\"nf_view_matches_acc\":{},\"record_want_stall_passes\":{},\"record_want_stall_ms\":{},\"private_network\":\"{}\"}}",
                            // ⛔ `blocks` NOW MEANS CHAIN HEIGHT, NOT THIS PROCESS'S IN-MEMORY COUNT.
                            //
                            // It used to report `n_blocks` — the blocks THIS PROCESS holds in memory. After an
                            // O(1) #106 resume that is a handful even on a chain 51,000 deep, because the node
                            // restores its state without replaying history, by design. Published as `blocks` it
                            // reads as chain height, so every restart looked like the chain had reset to ~0 and
                            // stalled. Reported live: `blocks=174` while `blue_score=50818` and climbing.
                            //
                            // The DAG height is the honest answer to "how many blocks"; the in-memory count is
                            // still served, under a name that says what it counts.
                            i.blue_score, i.n_blocks, i.n_tips, i.blue_score, i.blue_score, i.finalized_height, i.required_stamp_bits, i.params.dag_width, i.params.target_spacing_ms,
                             // A-F83: the halving interval this node's SAT schedule runs with (public, a compiled constant), so a
                             // check can show on a live node that the schedule and the mesh target are one source
                             crate::sat_schedule::HALVING_INTERVAL, txpb, tps, proving_power, chain_id, mesh_joined, mesh_joined_how, foreign_network_contacts, hex_encode(crate::params::process_network_id().as_bytes()), env!("MONEROUSD_BUILD_UNIX"), env!("MONEROUSD_BUILD_TIME"), env!("MONEROUSD_SRC_FINGERPRINT"), peer_count, live_contacts, live_contacts_delta, writers_held, onion_pub, own_addr, served_seq, records_held, record_top, rt.node().da_final_record_top(), history_complete, nf_fold_seq, hex_encode(rt.node().account_root().as_bytes()),
                            // ⛔⛔⛔ DB-229 — EACH ROOT IN THE SLOT ITS KEY NAMES. The key list reads
                            // `account_root, token_registry_root, membership_acc, unspent_root`, but the
                            // registry root was APPENDED after `nullifier_root()` when it was added, so every
                            // value after `account_root` sat one key to the left: `token_registry_root` served
                            // the membership accumulator, `membership_acc` served the nullifier root, and
                            // `unspent_root` served the TOKEN REGISTRY ROOT — all-zero on a chain with no
                            // assets. Every reader was misled at once: the ecosystem gate's step-3 "roots
                            // EQUAL" compared two all-zero registry roots (a check that could not fail —
                            // DB-211's vacuity, one layer down), step 1 read the nullifier root under the
                            // accumulator's name, and the AssetCreate real-node pin failed its precondition
                            // comparing a producer's advanced membership accumulator with a joiner's empty one.
                            // ROOT-LAYER: this argument list IS the serializer — the only place a value meets
                            // its name; no reader can recover a swapped field.
                            // MEASURED: real-node pin 2026-09-26 (binary 403d13ca) — `token_registry_root`
                            // served 128 hex chars (eight `{:016x}` limbs: the membership accumulator's
                            // format) where a 32-byte root serves 64; its peer, not yet caught up, served 128
                            // zeros. After: `get_info_serves_every_root_under_its_own_name` pins each field
                            // against the node method it is named for.
                            // MUST-STAY-GREEN: every /get_info key, the argument count (the format! macro
                            // checks it), `get_info_names_a_saturated_want_set_apart_from_a_debt_of_that_size`.
                            //
                            // ⭐ THE SMART-CONTRACT LAYER'S STATE ANCHOR. A caller proves a token exists by
                            // carrying its descriptor and a membership path against THIS root, so it has to
                            // be served like any other chain root. It is a ROOT, not an observed count, so
                            // this surface's no-volume law is untouched.
                            rt.node().token_registry_root().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                            rt.node().membership_acc().iter().map(|w| format!("{w:016x}")).collect::<String>(),
                            rt.node().nullifier_root().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                            pp_lock_wait, pp_grind, pp_cycle, pp_blocks, pp_fails, tip_work, tick_passes, tick_last_ms, tick_blocks, ip_att, ip_tmpl, ip_mine, ip_graft, bp_slots, bp_jobs, bp_tmpl_none, tmpl_ms, graft_ms, g_relay, g_uns, g_rec, g_bond, ing_blocks, ing_verify, ing_graft, ing_apply, ing_save, ing_pow, ing_settle, unspent_serve_ready, wanted_records, wanted_ids, missing_records, mw_ord, mw_rid, mw_da_id, mw_da_ord, mw_gap, missing_want_cap, missing_wants_saturated, note_payload_debt, sidecar_gap_count, fold_unfolded, fold_wait_passes, fold_wedged, nf_view_present, nf_view_matches_acc, record_want_stall_passes, record_want_stall_ms, crate::pqmix::network_state()
                        ),
                    )
                }
                _ => (200, err_json("UNEXPECTED_RESPONSE")),
            };
            if resp.0 == 200 && resp.1.starts_with("{\"status\":\"OK\",\"blocks\"") {
                *get_info_cache().lock().unwrap_or_else(|e| e.into_inner()) = resp.1.clone();
            }
            resp
        }
        // ⭐⭐⭐ THE OPERATOR DIAGNOSTICS ROUTE — the readouts this node already computes and nobody
        // could read.
        //
        // ⛔ WHY IT IS NOT `/get_info`. That surface carries a written law: *"serves ONLY chain-progress +
        // anti-spam difficulty + PARAM-DERIVED cover-rate metrics — NEVER an observed volume/supply/count
        // figure"*, which is why `mempool_txs` and `mempool_weight` are deliberately absent from it. Some
        // of the readouts below ARE observed counts, so putting them there would break that contract for
        // every wallet and app that consumes it.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: this is a node reporting its OWN process state to its OWN
        // operator over the loopback RPC (127.0.0.1), which is not the surface the pillar governs — that
        // one is "viewing the CHAIN as any node, indexer, validator or global adversary". Nothing here is
        // gossiped, served to a peer, or reachable off this machine, and no field names a tag, note,
        // amount, key, owner or counterparty. `payments_in_flight` and the pruned-spend count are
        // deliberately HERE and deliberately not on `/get_info` for exactly that reason.
        ("GET", "/node_diagnostics") | ("POST", "/node_diagnostics") => {
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (queued, (last_in_ms, legs), unacked, draining, classes) = rt.channel_health();
            let n = rt.node();
            let (sparse_nodes, imt_leaves, da_blocks, da_bytes, note_clues) = n.mem_attrib();
            let (m2a, m2b, m2c) = n.mem_attrib2();
            let delivery: String = classes
                .iter()
                .map(|(name, n, left)| format!("{{\"class\":\"{name}\",\"queued\":{n},\"left\":{left}}}"))
                .collect::<Vec<_>>()
                .join(",");
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"link\":{{\"queued_cells\":{queued},\"last_inbound_ms\":{last_in_ms},\"live_legs\":{legs},\"unacked_payment_messages\":{unacked},\"draining\":{draining},\"delivery\":[{delivery}]}},\"da\":{{\"reads\":{},\"note_blocks_applied\":{}}},\"ram\":{{\"sparse_nodes\":{sparse_nodes},\"imt_leaves\":{imt_leaves},\"da_blocks\":{da_blocks},\"da_bytes\":{da_bytes},\"note_clues\":{note_clues},\"tier2\":[{m2a},{m2b},{m2c}]}},\"fold\":{{\"pruned_double_spends\":{}}},\"sync\":{{\"jumped\":{}}},\"payments_in_flight\":{},\"dsol\":{{\"assets\":{},\"registry_peaks\":{}}}}}",
                    n.da_read_count(),
                    n.dag_len(),
                    n.pruned_double_spends().len(),
                    n.synced_state().is_some(),
                    n.payments_in_flight(),
                    n.dsol_registry_size().0,
                    n.dsol_registry_size().1,
                ),
            )
        }
        ("GET", "/record_holding") => {
            // ⭐ THE RECORD-HOLDING SPLIT — WHY `records_held` lags `record_top`, in three counts.
            //
            // ROOT-LAYER: every number here is PRODUCED by node.rs's own maintained state — the
            // ordinal row map (`da_ord_mem` via `da_records_held`), the spend-fold gap set
            // (`uns_spendfold_gap` via `missing_record_breakdown`), the spine cursor
            // (`certified_record_position`) and the want sets. This route is a pure O(1) projection
            // of those producer-owned counts at the serve layer; it computes nothing of its own and
            // adds no second producer, so it cannot drift from what the node itself acts on.
            //
            // MEASURED: 2026-09-04, my own read of /get_info on the live pair (build
            // 81578d55d825e09d) — BEFORE this route the gap is unexplained: :27780 records_held 197 /
            // record_top 7306 (7109 records absent) with `missing_records` naming only 65 and
            // sidecar_gap_count 3243; :28901 records_held 4099 / record_top 8627 (4528 absent) with
            // `missing_records` 68. No served field states the absent count or which class owns it —
            // the want machinery visibly names under 1% of it. AFTER: the split is one read; the
            // in-process pin `record_holding_split_sums_to_record_top_and_names_the_absent_class`
            // asserts the sum law and the class movement across a produce.
            //
            // MUST-STAY-GREEN: the full rpc_http route-table sweep and the /get_info tests — this is
            // a read-only route that writes no state and touches no existing field.
            //
            // The three classes PARTITION the ordinal space exactly:
            //   bytes_absent     := record_top - records_held — ordinals with NO held record row
            //                       (`da_ord_mem` has no entry), so this node can neither serve nor
            //                       vouch their bytes.
            //   present_unfolded := the spend-fold gap set — records this node holds whose fold the
            //                       unspent set still awaits (the node's own self-heal backlog; the
            //                       same set READY reads via `sidecar_gap_count`).
            //   folded_held      := records_held - present_unfolded — held rows the node's own
            //                       readiness law counts as fold-covered (held and not awaiting fold).
            //
            // The sum is record_top BY ARITHMETIC, so a reader cross-checks it as a self-audit. One
            // caveat, stated rather than hidden: the gap set is keyed by block id, so a gap entry for
            // a block whose record row never landed would overlap `bytes_absent`; the `min` +
            // `saturating_sub` pair keeps the three-way total exact under that overlap instead of
            // serving a sum that fails its own law, and `certified_position` beside it exposes the
            // fold cursor so that shape is visible instead of silent.
            //
            // EVERY field is an O(1) indexed read of a count the node already maintains — no walk over
            // the ordinal space, no growth with history (the O(1)-serve law; a per-ordinal census here
            // is exactly the banned enumerate-the-shard shape).
            //
            // Read-only diagnostic for the roll gate and the Tier-1 discriminator — not polled by the
            // wallet. Digital-cash disclosure analysis: COUNTS ONLY over the constant-256 cover
            // stream, CONSTANT response shape (the same nine fields every call, healthy or holed).
            // Never an id, address, note, commitment, amount, key or owner — the same disclosure
            // class as records_held/record_top already on /get_info.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let record_top = rt.node().da_record_ordinal_top();
            let records_held = rt.node().da_records_held();
            let bytes_absent = record_top.saturating_sub(records_held);
            let (w_ord, w_ids, w_da_ids, w_da, spendfold_gap) =
                rt.node().missing_record_breakdown();
            let present_unfolded = (spendfold_gap as u64).min(records_held);
            let folded_held = records_held.saturating_sub(present_unfolded);
            let certified_position = rt.node().certified_record_position();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"record_top\":{},\"bytes_absent\":{},\"present_unfolded\":{},\"folded_held\":{},\"certified_position\":{},\"wanted_by_ordinal\":{},\"wanted_by_id\":{},\"da_wanted_ids\":{},\"da_wanted\":{}}}",
                    record_top,
                    bytes_absent,
                    present_unfolded,
                    folded_held,
                    certified_position,
                    w_ord,
                    w_ids,
                    w_da_ids,
                    w_da
                ),
            )
        }
        ("GET", "/get_solvency") | ("GET", "/reserves") => {
            // ⛔ READERS NEVER QUEUE BEHIND THE WRITER (performance cardinal). The runtime PUBLISHES this answer once per
            // tick while it already holds the lock (`publish_live_solvency`, beside `publish_live_status`), so this
            // read never waits on a block apply. Only a process that has not finished its first tick takes the lock.
            // ROOT-LAYER: the value is PRODUCED by the writer that holds the peg ledger, at the moment it holds it. A
            // reader-side cache would still have made the first busy read wait, and would have left the answer's age
            // decided by whichever request happened to win the lock.
            // MEASURED: ecosystem gate 2026-09-28 20:28 step 7: `/api/reserves` 503 (the sovereign loopback's 1.5 s
            // read timed out while one block apply held the lock 1.2-1.3 s; the same surface passed 9/9 at 20:09).
            // After: the next gate run on a binary with this change (recorded in docs/DEPLOY-GATE.md when run).
            // MUST-STAY-GREEN: the solvency body is byte-identical to before (one serializer, `solvency_body`); the
            // reserves page and every step-7 launchpad surface; `/get_info`'s DB-137 path is untouched.
            if let Some(b) = published_solvency() {
                return (200, b);
            }
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let peg = rt.node().peg();
            let (rc, mc, ratio) = (peg.reserve_commit(), peg.minted_commit(), peg.ratio_bps());
            drop(rt);
            (200, solvency_body(rc, mc, ratio))
        }
        ("GET", "/contract_state_root") | ("POST", "/contract_state_root") => {
            // ⭐ §BR-12 F13 — the ONE word of every deployed contract, for a wallet that must verify an app's claimed
            // manifest + storage root BEFORE it pays a publisher fee (the leaf's path must open this root).
            // DIGITAL-CASH-PRIVACY-REVIEWED: a public chain root and a height; nothing of any note, amount, key or owner.
            let guard = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = guard.node();
            let tip = node.selected_tip().and_then(|t| node.dag().get(&t).map(|n| n.blue_score)).unwrap_or(0);
            let root = hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(node.peg().contract_state_root()));
            drop(guard);
            (200, format!("{{\"status\":\"OK\",\"root\":\"{root}\",\"tip\":{tip}}}"))
        }
        ("GET", "/contract_leaves_from") | ("POST", "/contract_leaves_from") => {
            // ⭐ §BR-12 F13 — the contract-state TRANSITIONS the fold applied (`contract_state::ContractLeafUpdate`), from
            // the constant ring, for a follower that holds a contract's state (a publishing wallet, an app): it applies each
            // entry whose `pre` is its own root and ends on the chain's root, or learns it is behind the ring (`oldest`).
            // DIGITAL-CASH-PRIVACY-REVIEWED: contract ids and state digests already public in the carried objects' blocks.
            let from = json_num_field(body, "from").unwrap_or(0);
            let guard = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (root, rows, oldest) = guard.node().contract_leaf_updates_from(from);
            drop(guard);
            let h = |d: crate::spend_frontier::Digest4| hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(d));
            let items: Vec<String> = rows
                .iter()
                .map(|u| {
                    format!(
                        "{{\"blue\":{},\"pre\":\"{}\",\"cid\":\"{}\",\"leaf\":\"{}\",\"post\":\"{}\"}}",
                        u.blue,
                        h(u.pre),
                        hex_encode(&u.cid),
                        h(u.leaf),
                        h(u.post)
                    )
                })
                .collect();
            let oldest_s = oldest.map(|o| o.to_string()).unwrap_or_else(|| "null".to_string());
            (200, format!("{{\"status\":\"OK\",\"root\":\"{}\",\"oldest\":{oldest_s},\"updates\":[{}]}}", h(root), items.join(",")))
        }
        ("GET", "/contract_state_blob") | ("POST", "/contract_state_blob") => {
            // ⭐ D4 — one contract's last states (`contract_blobs`, at most KEEP, NEWEST first): each the sealed blob of a call
            // the fold applied, the whole post-state under the contract's key. A reader's wallet takes the newest whose slots
            // fold to the root the chain's contract leaf holds now (a rewound step leaves an orphan on top). `NONE` when this
            // node holds no record for the contract.
            // DIGITAL-CASH-PRIVACY-REVIEWED: what the carried call object already shows in its block (contract id, the
            // call's tx hash, the post-state root, a ciphertext under the contract's key); the asking wallet names a
            // contract it reads, as `/contract_leaves_from` readers already do on their own node.
            let Some(cid) = json_str_field(body, "cid").and_then(|h| hex_decode(&h)).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                return (400, "{\"status\":\"BAD\",\"error\":\"cid must be 32 bytes of hex\"}".to_string());
            };
            let kept = crate::contract_blobs::log().map(|mut l| l.recent(&cid)).unwrap_or_default();
            if kept.is_empty() {
                return (200, "{\"status\":\"NONE\"}".to_string());
            }
            let items: Vec<String> = kept
                .iter()
                .map(|r| {
                    format!(
                        "{{\"seq\":{},\"blue\":{},\"tx_hash\":\"{}\",\"salt\":\"{}\",\"post\":\"{}\",\"blob\":\"{}\"}}",
                        r.seq,
                        r.blue,
                        hex_encode(&r.tx_hash),
                        hex_encode(&r.salt),
                        hex_encode(&r.storage_post),
                        hex_encode(&r.blob)
                    )
                })
                .collect();
            (200, format!("{{\"status\":\"OK\",\"records\":[{}]}}", items.join(",")))
        }
        ("POST", "/applied_notes_from") | ("GET", "/applied_notes_from") => {
            // DB-88 (2026-09-19): the wallet that RUNS this node finds its money by trial-decapsulating the
            // real output notes of the blocks the node applied, in height order — no published account
            // target, no per-account index, nothing on the wire beyond the block itself (the note-discovery
            // memo's verdict; Zcash's trial decryption). Paged by the caller: `from_height` (a blue score),
            // `max_blocks` ≤ 256. A block whose notes this node no longer holds answers `null` notes, so the
            // caller's cursor stops there instead of skipping it.
            // DIGITAL-CASH-PRIVACY-REVIEWED: by construction — public chain bytes (the block's own notes),
            // queried by HEIGHT alone; nothing here names a key, tag, commitment, amount or owner.
            let from = json_num_field(body, "from_height").unwrap_or(0);
            let max = json_num_field(body, "max_blocks").unwrap_or(64) as usize;
            let guard = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = guard.node();
            let (tip, rows) = node.applied_real_note_members_from(from, max);
            let mut items: Vec<String> = Vec::with_capacity(rows.len());
            for (h, id, members) in rows {
                // ⭐ DB-223: `members` = `[[accepted block id, its note count], …]` in the order `notes_hex`
                // concatenates, so a wallet can cut each accepted block's own notes out (its RECORD's leaves).
                // ⭐ §20.2: `member_leaves` = each member's RECORD LEAVES (256 × 32 B, `leaf_to_cm_bytes`), one hex string per
                // member in the same order — a wallet holds no cover key, so it cannot lay a record's cover from its reals;
                // the leaves are the record's public header slots, served by the node that holds the record (null if not).
                let (notes_s, members_s, leaves_s) = match members {
                    Some(v) => {
                        let mut hx = String::with_capacity(v.iter().flat_map(|(_, ns)| ns).map(|n| n.len() * 2).sum());
                        let mut ms: Vec<String> = Vec::with_capacity(v.len());
                        let mut ls: Vec<String> = Vec::with_capacity(v.len());
                        for (b, ns) in &v {
                            for n in ns {
                                hx.push_str(&hex_encode(n));
                            }
                            ms.push(format!("[\"{}\",{}]", hex_encode(b.as_bytes()), ns.len()));
                            match node.da_block_leaves(node.record_addr_for_block_or_canonical(b)) {
                                Some(leaves) => {
                                    let mut lh = String::with_capacity(leaves.len() * 64);
                                    for l in leaves {
                                        lh.push_str(&hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(l)));
                                    }
                                    ls.push(format!("\"{lh}\""));
                                }
                                None => ls.push("null".to_string()),
                            }
                        }
                        (format!("\"{hx}\""), format!("[{}]", ms.join(",")), format!("[{}]", ls.join(",")))
                    }
                    None => ("null".to_string(), "null".to_string(), "null".to_string()),
                };
                items.push(format!(
                    "{{\"height\":{h},\"id\":\"{}\",\"notes_hex\":{notes_s},\"members\":{members_s},\"member_leaves\":{leaves_s}}}",
                    hex_encode(id.as_bytes())
                ));
            }
            drop(guard);
            (200, format!("{{\"status\":\"OK\",\"tip\":{tip},\"blocks\":[{}]}}", items.join(",")))
        }
        ("GET", "/get_height") | ("GET", "/get_tip") => {
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.rpc(RpcRequest::GetTip) {
                RpcResponse::Tip { tip, blue_score, finalized_height } => {
                    let tip_hex = tip
                        .map(|t| format!("\"{}\"", hex_encode(t.as_bytes())))
                        .unwrap_or_else(|| "null".to_string());
                    // the chain clock (median-time-past, `Node::chain_time_ms`) a wallet draws a cash-out's pay-after on and
                    // counts its wait down by
                    let (chain_ms, finalized_ms) = (rt.node().chain_time_ms(), rt.node().finalized_chain_time_ms());
                    // DIGITAL-CASH-PRIVACY-REVIEWED: chain heights, a block id and header-time medians — public DAG
                    // structure, nothing of any note, amount, key or owner.
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"blue_score\":{},\"height\":{},\"finalized_height\":{},\"tip\":{},\"chain_time_ms\":{chain_ms},\"finalized_chain_time_ms\":{finalized_ms}}}",
                            blue_score, blue_score, finalized_height, tip_hex
                        ),
                    )
                }
                _ => (200, err_json("UNEXPECTED_RESPONSE")),
            }
        }
        // ⛔ DEV/BENCH ONLY (`bench-routes`): seconds of proving per unauthenticated GET — a CPU-exhaustion door on a public
        // node (MEASURED 2026-10-06: > 10 s each in the route sweep). A shipped node answers this 404. cons: none for a node.
        #[cfg(feature = "bench-routes")]
        ("GET", "/xsender_recursive_settle") => {
            // ⭐ task #144/#145 — the FULL-PARITY node performs the FULL SOUND cross-sender CARRIER VERIFY ITSELF
            // (no standalone-bin workaround). N INDEPENDENT senders' carriers → ONE O(1) outer proof that verifies
            // BOTH halves of every carrier IN-CIRCUIT: the VALIDITY zerocheck chain AND the WHIR-PCS OPENING chain
            // (verify_hvzk/into_sumcheck — the step that binds each opened eval to the sender's commitment, so a
            // producer can NOT fabricate openings). FRI-free, NO witness/sk (privacy-preserving). The outer proof
            // stays ~constant as N grows (folded to height-1); forging EITHER half is rejected fail-closed. This is
            // verify_air_direct_light_decider_bytes recursed over N carriers — the sound, private cross-sender
            // settlement aggregate. Served so the live mesh proves it on the default (pure-Rust WHIR) node build.
            {
                use usdm_decider::whir_rec_block::xsender_carrier_verify_run;
                let sweep = [32usize, 128, 512, 1024];
                let mut rows = String::from("[");
                let (mut s0, mut sn, mut vn, mut nn) = (0usize, 0usize, 0u128, 0usize);
                for (idx, &n) in sweep.iter().enumerate() {
                    let (carrier, verify_us, ok) = xsender_carrier_verify_run(n, None);
                    if !ok {
                        return (200, err_json("CARRIER_VERIFY_FAILED"));
                    }
                    if idx == 0 {
                        s0 = carrier;
                    }
                    sn = carrier;
                    vn = verify_us;
                    nn = n;
                    if idx > 0 {
                        rows.push(',');
                    }
                    rows.push_str(&format!(
                        "{{\"n\":{},\"carrier_bytes\":{},\"verify_us\":{}}}",
                        n, carrier, verify_us
                    ));
                }
                rows.push(']');
                // adversarial: forge the VALIDITY half, then (separately) the OPENING half → EACH MUST reject fail-closed.
                let (_fvc, _fvu, forged_validity_ok) =
                    xsender_carrier_verify_run(nn, Some((false, 0)));
                let (_foc, _fou, forged_opening_ok) =
                    xsender_carrier_verify_run(nn, Some((true, 0)));
                let o1 = sn <= s0 + s0 / 2; // carrier within 1.5× over the whole sweep ⇒ O(1) ∀N
                (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"kind\":\"whir_sound_cross_sender_carrier_verify\",\"o1_carrier_constant\":{},\"in_circuit_opening_verifier\":true,\"forged_validity_rejected\":{},\"forged_opening_rejected\":{},\"settled_us_per_tx\":{:.4},\"sweep\":{}}}",
                        o1, !forged_validity_ok, !forged_opening_ok, vn as f64 / nn.max(1) as f64, rows
                    ),
                )
            }
        }
        #[cfg(feature = "bench-routes")] // DEV/BENCH ONLY — see `/xsender_recursive_settle` above
        ("GET", "/settled_tps_bench") => {
            // ⭐ SETTLED-TPS bench — the SETTLE side of end-to-end throughput. For each batch size N, the node
            // recursively settles N INDEPENDENT senders into ONE O(1) proof and times BOTH the prove (every
            // sender's own spend-proof + the producer's fold) and the O(1) verify. Reports:
            //   • settle_prove_tps  = N / prove_s   (the producer's own settle-build rate; parallelizable per node)
            //   • settle_verify_tps = N / verify_s  (how fast a DOWNSTREAM node settles a received block — O(1))
            // The sustained end-to-end SETTLED tps = min(admission_tps, settle_prove_tps) × node_count; verify is
            // O(1) so it never bottlenecks. The live-mesh harness combines this with the REAL sustained admission
            // load to report the network settled-tps vs VISA/Solana.
            {
                use usdm_decider::whir_rec_block::xsender_carrier_verify_bench;
                let sweep = [128usize, 512, 1024, 2048];
                let mut rows = String::from("[");
                let (mut best_prove_tps, mut best_verify_tps) = (0f64, 0f64);
                for (idx, &n) in sweep.iter().enumerate() {
                    let (carrier, prove_us, verify_us, ok) = xsender_carrier_verify_bench(n);
                    if !ok {
                        return (200, err_json("SETTLE_VERIFY_FAILED"));
                    }
                    let prove_tps = n as f64 / (prove_us as f64 / 1e6).max(1e-9);
                    let verify_tps = n as f64 / (verify_us as f64 / 1e6).max(1e-9);
                    best_prove_tps = best_prove_tps.max(prove_tps);
                    best_verify_tps = best_verify_tps.max(verify_tps);
                    if idx > 0 {
                        rows.push(',');
                    }
                    rows.push_str(&format!(
                        "{{\"n\":{},\"carrier_bytes\":{},\"prove_us\":{},\"verify_us\":{},\"settle_prove_tps\":{:.0},\"settle_verify_tps\":{:.0}}}",
                        n, carrier, prove_us, verify_us, prove_tps, verify_tps
                    ));
                }
                rows.push(']');
                (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"kind\":\"settled_tps_bench\",\"best_settle_prove_tps\":{:.0},\"best_settle_verify_tps\":{:.0},\"sweep\":{}}}",
                        best_prove_tps, best_verify_tps, rows
                    ),
                )
            }
        }
        #[cfg(feature = "bench-routes")] // DEV/BENCH ONLY — re-verifies the whole mempool per GET; see above
        ("GET", "/admission_drop_bench") => {
            // ⭐ THE ADMISSION-DROP, PROVEN ON REAL CARRIERS. A node WITHOUT the aggregate re-verifies EVERY tx's
            // PQ spend carrier (`pqspend_direct_verify_carrier`, ~ms each) — the redundant per-tx cost every node
            // pays today. WITH the block's recursive settlement aggregate, a downstream node verifies ONE O(1)
            // proof and settles the WHOLE block, DROPPING the per-tx re-verify. This times BOTH over the node's
            // OWN whole mempool of real carriers: OLD = Σ per-tx verify, NEW = one aggregate verify → the measured
            // speedup + the downstream tps before/after. (Flood the node first so its mempool holds real carriers.)
            {
                use std::time::Instant;
                // Under ONE lock: the REAL carriers (producer input) + their STORED tx-ids (the TRUE-O(1)
                // downstream verify binds against these ids the node already holds — never re-hashing bundles).
                let (blobs, tx_ids) = {
                    let rtg = rt.lock().unwrap_or_else(|e| e.into_inner());
                    let m = rtg.node().mempool();
                    (m.all_blobs(), m.all_tx_ids())
                };
                let n = blobs.len();
                if n == 0 {
                    return (200, err_json("MEMPOOL_EMPTY_FLOOD_FIRST"));
                }
                // OLD downstream cost: re-verify EVERY carrier (what the aggregate ELIMINATES).
                let t_old = Instant::now();
                let mut okc = 0usize;
                for b in &blobs {
                    if crate::whir_decider::pqspend_direct_verify_carrier(b).is_some() {
                        okc += 1;
                    }
                }
                let old_us = t_old.elapsed().as_micros().max(1);
                // The producer folds the REAL carriers into ONE O(1) `Block.settlement` aggregate (real bundle
                // extraction + WHIR-PCS opening in-circuit) — this is the PRODUCER's build cost, done once.
                let agg = usdm_decider::whir_rec_block::settlement_aggregate_from_carriers(&blobs);
                let agg_bytes = agg.as_ref().map(|a| a.len()).unwrap_or(0);
                // NEW downstream cost = the TRUE-O(1) verify: ONE proof against ONLY n + the tx-set root recomputed
                // from the stored tx-ids (blake3 over a few KB of ids) — NO carrier download/parse/re-hash. This is
                // exactly what `ingest_block` does, so it certifies the whole block of N and drops the per-tx verify.
                let (new_us, agg_ok) = match &agg {
                    Some(a) => {
                        let t = Instant::now();
                        let ok = usdm_decider::whir_rec_block::verify_settlement_aggregate_by_txids(
                            a, &tx_ids,
                        );
                        (t.elapsed().as_micros().max(1), ok)
                    }
                    None => (1u128, false), // some carrier not a decodable spend carrier (e.g. cover) → no aggregate
                };
                let old_tps = n as f64 / (old_us as f64 / 1e6);
                let new_tps = n as f64 / (new_us as f64 / 1e6);
                (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"kind\":\"admission_drop_bench\",\"real_carrier_aggregate\":true,\"n_real_carriers\":{},\"per_tx_verified_ok\":{},\"aggregate_bytes\":{},\"agg_ok\":{},\"OLD_per_tx_downstream_us\":{},\"NEW_aggregate_downstream_us\":{},\"OLD_downstream_tps\":{:.0},\"NEW_downstream_tps\":{:.0},\"admission_drop_speedup\":{:.1}}}",
                        n, okc, agg_bytes, agg_ok, old_us, new_us, old_tps, new_tps, old_us as f64 / new_us as f64
                    ),
                )
            }
        }
        ("POST", "/get_pq_notes") | ("GET", "/get_pq_notes") => {
            // The wallet pages confidential note ciphertexts by height: body `{"from_height":<u64>}` →
            // `{"status":"OK","notes":[{"height":h,"blob_hex":"<hex>"}],"top_height":<u64>}`. The wallet
            // decapsulates each blob LOCALLY with its own ML-KEM scan key — the node never sees the key,
            // so serving the public ciphertexts leaks nothing (Pillar-1). Returns an EMPTY notes array
            // (a valid, honest "no notes in this range yet") rather than 404, so the wallet's balance/scan
            // path succeeds instead of erroring.
            let from_height = json_num_field(body, "from_height").unwrap_or(0);
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐ THE WALLET NAMED AN ORDINAL — IF WE LACK IT, ASK FOR THAT RECORD.
            //
            // The wallet reaches this with a position its account bucket gave it in ONE lookup. If this node
            // holds no record there, the sequential note backfill would eventually walk to it — except it
            // cannot: a record is ~295 KB and a page carries ONE, while the chain adds ~2/second, so a
            // recipient node measured +132 records/min against its peer's +157 and fell FURTHER behind every
            // minute. Carrying the wallet's O(1) answer through to the wire is the fix: name the ordinal,
            // fetch that record. ([[project_oli_locator_pir_cold_restore]])
            // ⛔ NAME THE WHOLE RANGE THE WALLET IS STUCK ON, NOT ONE ORDINAL. A wallet that has caught up to
            // this node's servable top asks at exactly that position and waits there. Wanting a single record
            // means the next ask is stuck at the same place again, so a node whose payload trails its DAG can
            // never hand over the newest blocks — which are precisely where a payment just sent lives.
            // MEASURED on the recipient node: `blocks 3096 / served 2875`, so a fresh payment sat in the ~221
            // blocks it could not serve, and the wallet polled a position that never filled.
            //
            // The width is the fixed request constant the wire already pads to, so this asks for a CONSTANT
            // number of records however far behind the node is — O(1) per query, not a walk, and it converges
            // because each answered record retires its own want.
            {
                let n = rt.node_mut();
                // A wallet whose account bucket named a RECORD ID asks for that id here. It is not a dense
                // ordinal, so ALSO want it by id — otherwise the only node that can ever answer is one that
                // already holds the record, and a node that joined after the payment never can.
                n.want_record_at_id(from_height);
                for i in 0..crate::protocol::TX_REQ_FIXED_COUNT as u64 {
                    n.want_record_at_ordinal(from_height.saturating_add(i));
                }
            }
            // ⭐ ITEM-6 LOCK SCOPE (same class as /get_my_pq_notes): the rpc call IS the snapshot —
            // release the rt lock before the hex render below.
            let resp = rt.rpc(RpcRequest::GetPqNotes { from_height });
            drop(rt);
            match resp {
                RpcResponse::PqNotes { notes, top_height } => {
                    let mut arr = String::from("[");
                    for (i, (h, ct)) in notes.iter().enumerate() {
                        if i > 0 {
                            arr.push(',');
                        }
                        arr += &format!(
                            "{{\"height\":{},\"blob_hex\":\"{}\"}}",
                            h,
                            hex_encode(ct)
                        );
                    }
                    arr.push(']');
                    // ⛔ "NOTHING HERE" AND "NOT HERE YET" ARE DIFFERENT ANSWERS, AND CONFLATING THEM LOSES
                    // PAYMENTS. The line above registered a want for this ordinal, but that fetch completes
                    // LATER — so an empty page right now may mean the record is on its way, not that the
                    // range is barren. A wallet told "OK, no notes" advances its cursor past the range and
                    // never asks again: MEASURED on two peered nodes, a recipient reported `scanned 0` and a
                    // 0.0 balance after three sends that all returned ok, because its node answered empty
                    // while the record it had just asked for was still in flight.
                    //
                    // `pending` says which it is: true exactly when we served nothing AND the record the
                    // wallet named is one we do not hold — the answer is incomplete through no fault of the
                    // caller — so the wallet holds its cursor and asks again instead of skipping money. This
                    // reports only THIS node's own holdings, never who asked or what they own.
                    let pending = notes.is_empty() && from_height < top_height;
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"notes\":{},\"top_height\":{},\"pending\":{}}}",
                            arr, top_height, pending
                        ),
                    )
                }
                _ => (200, err_json("UNEXPECTED_RESPONSE")),
            }
        }
        // ── The wallet's native PQ RPC surface (monerousd-wallet-zkdag/core/pq-rpc.cjs) — every route the
        //    wallet's confidential-note + validator flows call, each served from REAL node state. ──
        ("POST", "/get_my_pq_notes") | ("GET", "/get_my_pq_notes") => {
            // Own-node loopback note serving: identical ciphertext paging to /get_pq_notes — the ANY-HEIGHT DA
            // stream. The node holds NO scan key (Pillar-1) — it serves the note ciphertexts and the wallet
            // decapsulates each LOCALLY with its own ML-KEM key, so "my notes" is resolved on the WALLET,
            // never here.
            //
            // ⭐ ITEM-6 LOCK SCOPE: every branch below takes the rt lock for the SNAPSHOT only (register
            // wants, clone the note bytes, read the top) and hex-formats the reply AFTER the guard drops.
            // The old shape held the lock across the whole hex render (~590 KB of formatting for one
            // record) — rt-lock time every RPC, the pump and production paid.
            //
            // ── ⭐ ITEM-12 (server half): BATCHED by-record-id serve — `"positions":[{"id":N,"slot":S}]`,
            // and the batch arm is taken ONLY when BOTH are stated: `positions` present AND
            // `by_record_id:true` (the documented contract shape — the wallet reader speaks exactly it; a
            // `positions` body without the flag falls through to the generic pager like any other body).
            // The width is the PROTOCOL constant `PQ_NOTES_BATCH_FIXED_COUNT` — never caller-chosen — and
            // a wider request is refused whole, loudly (a silent truncation would refuse money without
            // saying so). Every position MUST name its `slot` — the wallet reader always holds one (the
            // account bucket handed it (ordinal, slot)) — and a slotless position refuses the WHOLE batch
            // loudly: serving "all 256 slots" for it would clone ~295 KB per position under the rt lock
            // (~18.9 MB for a full-width batch), the exact lock-hold class ITEM-6 closed. Every note in
            // the reply carries its record ADDRESS and SLOT explicitly, so the reader never derives a
            // slot from array position (the measured lib.rs fund-loss class). Each position is the same
            // O(1) indexed read as the single form, batched on the wire; the transient reply rows are
            // dropped with the response.
            // ROOT-LAYER: this serve door is where the reply is PRODUCED — batching and lock scope are
            // properties of the producer of the response bytes, not of any reader; the wallet-side reader
            // change is item 12's other half and lands against this exact reply shape.
            // MEASURED: the wallet's detection pass issues its per-position asks as 64 SERIAL round-trips
            // (`OLI_FETCH_PAGES = 64`, wallet lib.rs:1070, the send at lib.rs:2509), and `[tick-slow]
            // drain held the rt lock` reached 8368 ms with 232 occurrences in one boot on the lock this
            // handler shares — the two figures this restructure exists to close.
            // MUST-STAY-GREEN: the single-position `by_record_id` reply stays BYTE-IDENTICAL in shape
            // (height/slot/blob_hex + pending — the fields the live wallet parses); the pq-notes wire
            // tests in this file; `a_batched_by_record_id_request_returns_every_named_slot_with_its_
            // record_address` below.
            let from_height = json_num_field(body, "from_height").unwrap_or(0);
            let has_positions = {
                let v: Option<serde_json::Value> = serde_json::from_str(body).ok();
                v.as_ref().and_then(|v| v.get("positions")).is_some()
            };
            // ROOT-LAYER: this dispatcher is where the reply PRODUCER is chosen — the batch arm is
            // gated on the FULL documented contract (`positions` AND `by_record_id:true`), never on
            // `positions` presence alone, so routing cannot drift from the shape the comment above
            // documents and the wallet reader speaks.
            // MEASURED: fix-round re-run of the item-12 pin (batch shape, slot addressing, width
            // refusal) stays green with the gate on both fields; a `positions` body without the flag
            // now answers the generic pager shape (no `batch` key) — asserted in the pin.
            // MUST-STAY-GREEN: item12_a_batched_by_record_id_request_serves_every_named_slot_with_
            // its_record_address; the single-position `by_record_id` reply shape; the pq-notes wire
            // tests in this file.
            // ⭐ DB-223 Q2 §11 (a): `by_ordinal` names each position by FOLD ORDINAL — the coordinate the OLI index now
            // carries (NOT A RECORD ADDRESS). It resolves through `da_addr_at_ordinal` ONLY, so an ordinal is never
            // read as an address (reading one number in two spaces is AGENTS.md §6's trap). An ordinal this node does
            // not hold is wanted by ordinal and answered `pending`. The reply rows are the `by_record_id` rows, each
            // naming the resolved `record_addr`.
            let by_ordinal = matches!(json_bool_field(body, "by_ordinal"), Some(true));
            if has_positions && (by_ordinal || matches!(json_bool_field(body, "by_record_id"), Some(true))) {
                let parsed: Option<Vec<(u64, Option<u64>)>> = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v.get("positions").cloned())
                    .and_then(|p| p.as_array().cloned())
                    .and_then(|arr| {
                        let mut out: Vec<(u64, Option<u64>)> = Vec::with_capacity(arr.len());
                        for e in &arr {
                            // A position without an `id` refuses the WHOLE batch — half-reading a
                            // malformed batch would serve some notes and silently skip money.
                            let id = e.get("id").and_then(|x| x.as_u64())?;
                            let slot = e.get("slot").and_then(|x| x.as_u64());
                            out.push((id, slot));
                        }
                        Some(out)
                    });
                let Some(entries) = parsed else {
                    return (200, err_json("MALFORMED_POSITIONS"));
                };
                if entries.len() > crate::protocol::PQ_NOTES_BATCH_FIXED_COUNT {
                    return (200, err_json("BATCH_WIDER_THAN_PROTOCOL_CONSTANT"));
                }
                // ROOT-LAYER: the batch contract requires every position to NAME its slot — enforced
                // here, before the rt lock, at the producer of the reply. The wallet reader always
                // holds one (the bucket handed it (ordinal, slot)); a slotless position previously
                // fell through to "serve all 256 slots", cloning ~295 KB per position under ONE
                // rt-lock hold (~18.9 MB for 64 such positions) — the exact lock-hold class ITEM-6
                // closed. Refused WHOLE and loudly: half-reading would serve some notes and silently
                // skip money.
                // MEASURED: 64 slotless positions = 64 × 256 × 1153 B ≈ 18.9 MB cloned under one
                // guard pre-fix; post-fix the request is refused before the lock is ever taken.
                // MUST-STAY-GREEN: item12 batch pin (slot-addressed byte asserts, width refusal,
                // malformed refusal); the single-position `by_record_id` reply shape.
                if entries.iter().any(|(_, slot)| slot.is_none()) {
                    return (200, err_json("BATCH_POSITION_NAMES_NO_SLOT"));
                }
                // (req, record_addr, pending, [(slot, one sealed note)]) — transient, dropped with the reply.
                let (rows, top) = {
                    let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                    let mut rows: Vec<(u64, u64, bool, Vec<(u64, Vec<u8>)>)> =
                        Vec::with_capacity(entries.len());
                    for (id, slot) in &entries {
                        if by_ordinal {
                            // NOT-AN-ADDRESS: `id` is a fold ordinal here, resolved or wanted as one, never both.
                            let Some(a) = g.node().da_addr_at_ordinal(*id) else {
                                g.node_mut().want_record_at_ordinal(*id);
                                rows.push((*id, u64::MAX, true, Vec::new()));
                                continue;
                            };
                            let held = g.node().da_record_notes(a);
                            let mut picked: Vec<(u64, Vec<u8>)> = Vec::new();
                            if let Some(b) = held.as_ref() {
                                for (idx, n) in b.chunks_exact(crate::cover::PQ_NOTE_BYTES).enumerate() {
                                    if *slot == Some(idx as u64) {
                                        picked.push((idx as u64, n.to_vec()));
                                    }
                                }
                            }
                            rows.push((*id, a, held.is_none(), picked));
                            continue;
                        }
                        // Same want registration as the single-position path: a record this node
                        // lacks is fetched by id through the proven heal plumbing.
                        g.node_mut().want_record_at_id(*id);
                        let addr = g.node().da_addr_at_ordinal(*id).unwrap_or(*id);
                        let blob = g
                            .node()
                            .da_record_notes(addr)
                            .or_else(|| g.node().da_record_notes(*id));
                        let mut notes: Vec<(u64, Vec<u8>)> = Vec::new();
                        if let Some(b) = blob.as_ref() {
                            // ROOT-LAYER: the note width is a property of the COVER encoding — the
                            // one crate constant `crate::cover::PQ_NOTE_BYTES` is its producer; a
                            // local re-statement here could silently drift from it.
                            // MEASURED: fix-round — same value (1153), byte-identical slicing; the
                            // item-12 pin's slot-addressed byte asserts stay green.
                            // MUST-STAY-GREEN: item12 batch pin; the pq-notes wire tests.
                            let mut off = 0usize;
                            let mut idx = 0u64;
                            while off + crate::cover::PQ_NOTE_BYTES <= b.len() {
                                if *slot == Some(idx) {
                                    notes.push((idx, b[off..off + crate::cover::PQ_NOTE_BYTES].to_vec()));
                                }
                                off += crate::cover::PQ_NOTE_BYTES;
                                idx += 1;
                            }
                        }
                        rows.push((*id, addr, blob.is_none(), notes));
                    }
                    let top = g.node().da_highest_record_ordinal().unwrap_or(0);
                    (rows, top)
                }; // ← guard dropped; the hex render below never holds the rt lock
                let mut out = String::from("{\"status\":\"OK\",\"batch\":[");
                for (i, (req, addr, pending, notes)) in rows.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out += &format!(
                        "{{\"req\":{req},\"record_addr\":{addr},\"pending\":{pending},\"notes\":["
                    );
                    for (j, (slot, bytes)) in notes.iter().enumerate() {
                        if j > 0 {
                            out.push(',');
                        }
                        out += &format!(
                            "{{\"record_addr\":{},\"slot\":{},\"height\":{},\"blob_hex\":\"{}\"}}",
                            addr,
                            slot,
                            req,
                            hex_encode(bytes)
                        );
                    }
                    out += "]}";
                }
                out += &format!("],\"top_height\":{top}}}");
                return (200, out);
            }
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            {
                // ⛔ THIS is the route a wallet uses to fetch the record its ACCOUNT BUCKET named, and the id it
                // passes is the canonical BLOCK-DERIVED record id — not a dense ordinal. A node that joined
                // after the payment holds no record for it and, until now, had no way to ask: measured as
                // `[fetch_note_at] seq=43595999149800100 slot=172: the node served 0 note(s)` forever, wallet
                // pinned at 0.0 while a node holding the record served the same seed 0.55 / 5.
                // ...but ONLY when the caller says this is a RECORD ID. The same route is also paged with
                // ordinary stream cursors, and `wanted_record_ids` is bounded to `TX_REQ_FIXED_COUNT` — so
                // registering every call fills the set with cursors and crowds out the one id that matters.
                //
                // The caller knows which coordinate it holds, so it states it (`by_record_id`). Inferring it
                // from MAGNITUDE worked but was a heuristic dressed as consensus logic — it compared against
                // the tip, which reads as a height gate and would silently change behaviour as the chain grew.
                // An explicit flag cannot drift.
                if json_bool_field(body, "by_record_id").unwrap_or(false) {
                    rt.node_mut().want_record_at_id(from_height);
                }
            }
            // ⛔⛔⛔ ANSWER THE ONE RECORD ASKED FOR — NEVER A FORWARD PAGE FROM IT. When the caller names a
            // RECORD ID it wants exactly that record's notes; the generic path instead pages FORWARD from the
            // given position, so the reply grows with the chain rather than with what was asked.
            //
            // MEASURED: a wallet asking for the single record holding ONE note received 38,289,452 bytes —
            // ~130x a record's own 256 x 1153 = 295 KB — and spent 51.6s of a 52.2s cold restore moving and
            // parsing it, while the node's own lookup took 2ms and the RPC 220ms. That is the O(1) violation
            // the pillars forbid: the answer's SIZE grew with height, so "scan" could never be instant however
            // fast the index got.
            //
            // One named record in, that record's notes out. No cursor, no page, no term in chain height.
            if json_bool_field(body, "by_record_id").unwrap_or(false) {
                // The caller's value may be a dense ORDINAL (the wallet resolves its commitment to THIS
                // node's ordinal first) or a block-derived RECORD ID (straight from the account bucket, when
                // this node cannot place the commitment). Try the ordinal mapping first, then the raw id —
                // never guess, and answer nothing if neither places it.
                let addr = rt
                    .node()
                    .da_addr_at_ordinal(from_height)
                    .unwrap_or(from_height);
                let notes = rt
                    .node()
                    .da_record_notes(addr)
                    .or_else(|| rt.node().da_record_notes(from_height));
                let top = rt.node().da_highest_record_ordinal().unwrap_or(0);
                // ⭐ ITEM-6: the snapshot above is complete — release the rt lock BEFORE the hex render.
                drop(rt);
                // ⭐⭐⭐ SERVE THE NAMED SLOT, NOT THE WHOLE RECORD. The caller knows exactly which slot its
                // note sits in — the account bucket handed it (ordinal, slot) — so shipping all 256 notes is
                // 295 KB to deliver 1,153 bytes.
                //
                // That is not merely wasteful, it is why the answer never arrived: a 295 KB reply is ~73
                // transport cells, and MEASURED on the live mesh, node B logged `answering 1 of the named
                // record(s)` 448 times while node A's inbound showed ZERO `NotesResp` — every other message
                // type crossed the same link fine (TxResp 2,587, Block 1,537), and all of those are ~4 cells
                // or fewer. One note is ONE cell, which is the shape the constant-rate transport is built for.
                //
                // DIGITAL-CASH-PRIVACY-REVIEWED: the slot is chosen by the CALLER, who already knows it, and
                // the request set is cover-padded upstream; serving one sealed note reveals nothing the caller
                // did not name, and the reply SIZE stops varying with how much of a record is real.
                let want_slot = json_num_field(body, "slot");
                let mut arr = String::from("[");
                if let Some(blob) = notes.as_ref() {
                    const PQ_NOTE_BYTES: usize = 1153;
                    let mut off = 0usize;
                    let mut idx = 0u64;
                    let mut first = true;
                    while off + PQ_NOTE_BYTES <= blob.len() {
                        if want_slot.map(|w| w == idx).unwrap_or(true) {
                            if !first {
                                arr.push(',');
                            }
                            first = false;
                            arr.push_str(&format!(
                                "{{\"height\":{},\"slot\":{},\"blob_hex\":\"{}\"}}",
                                from_height,
                                idx,
                                hex_encode(&blob[off..off + PQ_NOTE_BYTES])
                            ));
                        }
                        off += PQ_NOTE_BYTES;
                        idx += 1;
                    }
                }
                arr.push(']');
                let pending = notes.is_none();
                return (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"notes\":{arr},\"top_height\":{top},\"pending\":{pending}}}"
                    ),
                );
            }
            // Generic stream page: the rpc call IS the snapshot — release the lock before formatting.
            let resp = rt.rpc(RpcRequest::GetPqNotes { from_height });
            drop(rt);
            match resp {
                RpcResponse::PqNotes { notes, top_height } => {
                    let mut arr = String::from("[");
                    for (i, (h, ct)) in notes.iter().enumerate() {
                        if i > 0 {
                            arr.push(',');
                        }
                        arr += &format!(
                            "{{\"height\":{},\"blob_hex\":\"{}\"}}",
                            h,
                            hex_encode(ct)
                        );
                    }
                    arr.push(']');
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"notes\":{},\"top_height\":{}}}",
                            arr, top_height
                        ),
                    )
                }
                _ => (200, err_json("UNEXPECTED_RESPONSE")),
            }
        }
        // /register_pq_scan_key REMOVED (Pillar-1, user 2026-07-10): the node accepts NO scan key on ANY endpoint.
        // Note recovery is fetch-all-then-decapsulate-LOCALLY — the wallet decaps the /get_my_pq_notes ciphertexts
        // in-process (scan key never leaves the wallet). An endpoint that ACCEPTS a scan key is a latent linkage-leak
        // surface (an operator could cluster a caller's notes), so it is deleted at the source, not gated.
        // /get_pq_nf_spent REMOVED (DIGITAL-CASH, user 2026-07-15). Same class as /check_nullifiers_spent above: a
        // by-nullifier spent-status oracle is a which-item + timing leak, no matter that the queried nullifier is
        // already on-chain — the node must never answer "is X spent?". Spend-status is resolved LOCALLY in the
        // wallet (its in-process node checks its own tree; a thin client scans the block stream it syncs). Deleted
        // at the source.
        ("POST", "/get_pq_output_tree") | ("GET", "/get_pq_output_tree") => {
            // The REAL note frontier (HF46): its fixed depth-32 root + leaf count + the FULL leaf set
            // (`notes_hex` = every note_cm in append order). The wallet rebuilds the identical depth-32 tree from
            // `notes_hex`, finds its own note's leaf index, and builds its copath.
            //   • `root`  = the blake3 note-visibility/DA frontier root (fetch/visibility anchor).
            //   • `spend_root` = the POSEIDON spend frontier anchor (`spend_frontier_root()` serialized as 32
            //     bytes = 4 LE KoalaBear limbs the wallet unpacks with `cm_bytes_to_leaf`); the in-circuit hash
            //     is Poseidon (blake3 is too costly in-circuit). Public commitments only (no amount/identity — Pillar-1).
            // ⭐ O(1) LIGHT MODE (user 2026-07-24 "scans and syncs should be instant"): a wallet self-builds its
            // membership copath from ONLY the DEPTH-32 `spend_peaks_hex` accumulator — never the full leaf set.
            // `light=1` OMITS + skips computing that leaf serve, so the response is CONSTANT-size (peaks + roots)
            // regardless of chain height; the explorer's full-tree view omits `light` and still gets every leaf.
            // O1-INFINITY-REVIEWED: the light branch is count-INDEPENDENT by construction — metric = f(DEPTH=32
            // peaks + fixed 32-byte roots), never the leaf total; the `note_leaves_hex` it REMOVES from the wallet
            // path is the OLD leaf-total payload, named here only to document what the fix drops.
            let light = json_num_field(body, "light").unwrap_or(0) == 1;
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = rt.node();
            let notes_hex = if light {
                String::new()
            } else {
                node.note_leaves_hex()
            };
            (
                200,
                format!(
                "{{\"status\":\"OK\",\"root\":\"{}\",\"depth\":{},\"count\":{},\"spend_root\":\"{}\",\"spend_count\":{},\"notes_hex\":\"{}\",\"spend_peaks_hex\":\"{}\",\"root_history_root\":\"{}\",\"root_history_count\":{},\"root_history_peaks_hex\":\"{}\"}}", // DIGITAL-CASH-PRIVACY-REVIEWED: count/spend_count == 256×height is the CONSTANT-256-cover frontier shape (every block appends exactly BLOCK_FIXED_NOTE_COUNT leaves, real + secret-seeded cover), so it reveals chain HEIGHT only (already served by /get_info) and NEVER real tx volume / which-item / ordering; spend_peaks_hex is the O(DEPTH) Poseidon decomposition of the SAME accumulator whose root spend_root is already served — a wallet self-builds its note membership copath against it (no O(n) leaf serve), no value/identity/linkage. root_history_root/peaks are the O(DEPTH) accumulator of PER-BLOCK spend anchors (one Poseidon-committed root per block, count == chain height already served); a wallet folds these to keep its note's RECEIPT anchor provable without re-observing the note stream, and the anchor itself stays PRIVATE in the spend circuit — reveals height only, never value/identity/linkage/which-item.
                hex_encode(node.note_frontier_root().as_bytes()),
                crate::spend_frontier::SPEND_TREE_DEPTH,
                node.note_frontier_count(),
                hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(node.spend_frontier_root())),
                node.spend_frontier_count(),
                notes_hex,
                node.spend_frontier_peaks_hex(),
                hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(node.root_history_root())),
                node.root_history_count(),
                node.root_history_peaks_hex()
            ),
            )
        }
        ("POST", "/get_nf_copath") | ("GET", "/get_nf_copath") => {
            // ⭐⭐⭐ THE SPENDER FETCHES ITS OWN NON-MEMBERSHIP WITNESS. (user 2026-07-30: "lets make the
            // spender hold its own witness".)
            //
            // MEASURED, the exact live blocker: `[nf-gate] witness source for input 0: local-index-fallback
            // (carried=0 of 32 inputs)`. `PqTx` has always had `nullifier_witnesses`, the RPC has always
            // parsed `nullifier_witnesses_hex` into it, and the gate now prefers it — but NOTHING SERVED the
            // copath, so the production send shipped zero and the node fell back to a local index that cannot
            // work at 150k blocks. This is the missing half.
            //
            // Returns the postcard `Vec<CompressedCopath>` the tx field takes verbatim, one per requested tag.
            // Compressed because a sparse copath is nearly all empty-subtree roots: only levels where another
            // spent tag shares a prefix carry a sibling, so the bitmap makes this a few hundred bytes, not 8 KB.
            //
            // TRUSTLESS: the spender self-verifies by folding — a wrong copath fails `verify_unspent` against
            // the same root the node checks, so a lying node can only make its own user's spend fail, never
            // forge one. Nothing here is authority; it is public data the wallet could derive itself.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: this is a which-item query BY CONSTRUCTION — the caller asks
            // about tags it is about to spend. It is answered with a CONSTANT-shaped reply for the FULL padded
            // width the caller sends (the 32-tag cover set, reals indistinguishable from decoys), the tags are
            // the caller's own, and the sibling values are chain-public interior nodes of the accumulator that
            // every block header already commits. No amount, key, owner or ordering is revealed, and the reply
            // size does not vary with how many of the tags are real.
            let tags_hex = json_str_field(body, "tags_hex").unwrap_or_default();
            let raw = hex_decode(&tags_hex).unwrap_or_default();
            if raw.is_empty() || raw.len() % 32 != 0 {
                (400, "{\"status\":\"ERR\",\"error\":\"tags_hex must be a non-empty multiple of 32 bytes\"}".to_string())
            } else {
                let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
                // ⛔⛔⛔ NEVER SERVE A COPATH THAT CANNOT DESCRIBE THIS NODE'S OWN ROOT.
                //
                // `da_sparse_copath` reads the node's copath index and substitutes the empty-subtree constant
                // for any level it lacks. When the index does not describe the live root — which is the normal
                // state, because the block-adopt paths advance the root WITHOUT mirroring paths (mirroring
                // measured at ~2.5 MB/block and was reverted) — it happily returns a well-formed copath that
                // folds to neither the empty nor the spent leaf.
                //
                // The wallet then CARRIES that copath, the gate returns `Unprovable`, and the user is told
                // "the note is already spent on-chain, or the witness is missing/stale/forged". Every word of
                // that is wrong: the note is untouched and the witness came from this very node. Serving a
                // confident wrong answer is the same defect class as the dropped query string — the node
                // answered a question it could not answer.
                //
                // A self-check costs one fold against the root we are about to be judged by. If the copath we
                // built yields no verdict, we cannot serve it, and we say so.
                // ⭐ Z2 — THIS NODE SERVES ITS OWN SHARDS. A tag outside them is not a failure of this
                // node's index, it is a CUSTODY fact: some other holder of that shard answers it. Saying so
                // separately is what lets a wallet route the ask instead of concluding its note is stuck.
                let mut foreign_shard = 0usize;
                let mut unprovable = 0usize;
                let mut out: Vec<crate::nf_sparse::CompressedCopath> =
                    Vec::with_capacity(raw.len() / 32);
                for chunk in raw.chunks_exact(32) {
                    let mut tag = [0u8; 32];
                    tag.copy_from_slice(chunk);
                    if !rt.node().holds_nf_shard(&tag) {
                        foreign_shard += 1;
                    }
                    // the ONE carry rule (`Node::carriable_copath`): judged at the admit authority this route's answer will
                    // be judged by, never at the accumulator alone
                    match rt.node().carriable_copath(&tag) {
                        Some(copath) => out.push(crate::nf_sparse::compress_copath(&copath)),
                        None => unprovable += 1,
                    }
                }
                if foreign_shard > 0 {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT out of a constant-width padded request, plus
                    // this node's own public shard policy. No tag, amount, key, owner or ordering.
                    let (bits, owned) = rt.node().nf_shard_state();
                    return (
                        503,
                        format!(
                            "{{\"status\":\"ERR\",\"foreign_shard\":{foreign_shard},\"of\":{},\"nf_shard_bits\":{bits},\"nf_shards_owned\":{owned},\"error\":\"this node \
                             holds no leaves for that nullifier shard, so it can build no witness for it. \
                             Your note is UNSPENT and untouched; ask a node that holds the shard.\"}}",
                            out.len()
                        ),
                    );
                }
                if unprovable > 0 {
                    // ⭐ CARRY NONE (lane funds-brb27): a copath this node's own door would refuse is not served — and that is
                    // an ANSWER, not an error: the spend carries no copath set and is admitted on its base-state absence
                    // witness and the node's own verdicts (every ordinary send's shape). Before, this was a 503 that the
                    // wallet read as "nothing was broadcast", so a send during a pending band step could never go.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a count of unservable positions out of a CONSTANT-width padded
                    // request. No tag, amount, key, owner or ordering — and the width is the same whatever the caller
                    // is really spending.
                    return (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"count\":0,\"carry\":false,\"unprovable\":{unprovable},\"of\":{},\"witnesses_hex\":\"\"}}",
                            raw.len() / 32
                        ),
                    );
                }
                match postcard::to_allocvec(&out) {
                    Ok(b) => (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"count\":{},\"witnesses_hex\":\"{}\"}}",
                            out.len(),
                            hex_encode(&b)
                        ),
                    ),
                    Err(_) => (500, "{\"status\":\"ERR\",\"error\":\"encode\"}".to_string()),
                }
            }
        }
        ("POST", "/get_nullifier_root") | ("GET", "/get_nullifier_root") => {
            // ⭐ O(1) — the sparse nullifier accumulator ROOT + count, the two constant-size values a wallet needs
            // to SELF-VERIFY a witness it built locally. This REPLACES `/get_nullifier_stream` for the send path:
            // the old model fetched the whole stream to rebuild a tree, which is the O(N) tree-rebuild the treeless
            // architecture retired, and which HANGS on a node whose DA cannot reproduce the stream. A wallet
            // maintains its own note's copath incrementally (`nf_sparse::OwnedCoverSet`) and checks it against this
            // root — no stream, no tree, no whole-history replay under the node lock.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let root_hex = hex_encode(&rt.node().nullifier_root());
            // ⭐ THE COPATH LANE'S OWN ROOT. `root_hex` is A_tip — the order-free consensus fold — and no
            // Merkle copath can ever verify against it. A caller folding a served `/get_nf_copath`
            // witness must fold against the MERKLE view those copaths come from, so it is served beside
            // it under its own name rather than silently swapped in. Display verdicts only; admission
            // runs on the recursive absence carrier bound to A_tip.
            let sparse_root_hex = hex_encode(&rt.node().sparse_merkle_root());
            let count = rt.node().nullifier_count();
            // Z2: the shard policy rides the root answer, so a wallet routing a copath ask knows both what
            // this node can serve and how wide the partition is. Counts of a LOCAL custody policy only —
            // never a note, amount, owner or which-item signal.
            let (shard_bits, shards_owned) = rt.node().nf_shard_state();
            // The HEIGHT that produced this root — a wallet's verdict is about a view, and a view that
            // lags is why the tri-state exists (DB-97). Chain progress only; already public.
            let height = rt.node().tip_height();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"root_hex\":\"{root_hex}\",\"sparse_root_hex\":\"{sparse_root_hex}\",\"count\":{count},\"height\":{height},\"nf_shard_bits\":{shard_bits},\"nf_shards_owned\":{shards_owned}}}"
                ),
            )
        }
        ("POST", "/get_nf_unspent_acc") | ("GET", "/get_nf_unspent_acc") => {
            // ⭐⭐⭐ O(1) A_TIP — the FOLD-NOT-HOLD nf-unspent accumulator (`nf_unspent_acc`) a wallet's O(1) absence
            // carrier binds to (`nf_sparse_air::verify_nf_absence_chain(…, a_tip)`). FIXED 32 bytes at ANY chain
            // height. A spender fetches it to FINALIZE/self-verify its incrementally-maintained recursive absence
            // proof right before a send; `blocks` is the applied-block count so the wallet knows how many O(1) fold
            // STEPS its self-overwriting carrier must already cover. NO stream, NO tree, NO whole-history replay.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let a_tip = rt.node().nf_unspent_acc();
            // A_tip is a compression output (canonical limbs), so it travels in the canonical 32-byte
            // injective form — the same form `Node::a_tip_root_bytes` projects. ⛔ §AG CLASS 9 lived here:
            // eight lanes written into a literal `[0u8; 32]` PANICKED this route at lane 4 on every
            // request (`range end index 40 out of range for slice of length 32`, measured 2026-09-13).
            let acc_hex = hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(a_tip));
            let blocks = rt.node().nf_blocks_applied_count();
            (
                200,
                format!("{{\"status\":\"OK\",\"a_tip_hex\":\"{acc_hex}\",\"blocks\":{blocks}}}"),
            )
        }
        ("POST", "/membership_roots") | ("GET", "/membership_roots") => {
            // The ordered block ROOTS a wallet's `NoteMembershipCarrier` folds. A wallet cannot enumerate
            // block ids itself, so without this the carrier is unbuildable — it must fold exactly the blocks
            // THIS node folded, and this is the only place that set is knowable.
            //
            // `from_topo` pages forward; a wallet that adopted a certified fold point starts there and folds
            // only FORWARD, so the work is bounded by how far behind it is, not by the chain's age.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: a block root is a fold of the constant 256-slot shape EVERY
            // block wears — identical whether the block settled payments or not. Same bytes for every caller,
            // no selector, no which-item question, no real count.
            let from_topo = json_num_field(body, "from_topo").unwrap_or(0);
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let roots = rt.node().membership_roots_from(from_topo, 4096);
            let mut arr = String::from("[");
            for (i, (topo, root)) in roots.iter().enumerate() {
                if i > 0 {
                    arr.push(',');
                }
                // The membership family travels as RAW LANES (`digest_to_lane_bytes`, `8 × DIGEST_LANES`
                // bytes): the accumulator these roots fold into is a wrapping SUM whose limbs are not
                // canonical, so the family shares the one lossless form and a wallet decodes all of it
                // with one function. ⛔ §AG class 9 lived here — eight lanes into a literal `[0u8; 32]`.
                arr.push_str(&format!(
                    "{{\"topo\":{},\"root_hex\":\"{}\"}}",
                    topo,
                    hex_encode(&crate::spend_frontier::digest_to_lane_bytes(root))
                ));
            }
            arr.push(']');
            (200, format!("{{\"status\":\"OK\",\"roots\":{arr}}}"))
        }
        ("POST", "/membership_transition") | ("GET", "/membership_transition") => {
            // ⭐ THE ONE FOLD TRANSITION AT AN ORDINAL — `(acc_before, block_root, acc_after)`, three indexed
            // reads. This is what a spender's carrier needs instead of `/membership_roots`: that route serves
            // an ARRAY of every root from an ordinal, which the wallet then re-folds, and it pages — so a
            // note past the page never had its own block's root in the fold at all.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: a block root and two folds of block roots — already-public chain
            // structure that /get_membership_acc serves to everyone. The 256-slot shape a root commits is the
            // same whether the block settled payments or not. It names no note, amount, owner or key, and the
            // answer is identical for every caller (selector-independent, no which-item question).
            let ordinal = json_num_field(body, "ordinal").unwrap_or(0);
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐⭐⭐ RECONCILE THE COORDINATE AT THE SERVE EDGE — the caller may hold EITHER space.
            //
            // A wallet's note position is the record's CANONICAL ADDRESS (height<<8|sub or block-id-derived,
            // ~10^16); this route's index is keyed by the DENSE fold ORDINAL. The wallet passed its address
            // here, the lookup either missed (one-step silently fell back to the series fold) or — worse —
            // landed on an unrelated ordinal, and the carrier then attested a transition for a DIFFERENT
            // record than the copath's: measured live 2026-08-12 as `[membership] refused: the carried proof
            // does not attest the transition it names`. The tree's own rule (da_block_root_at_ordinal doc):
            // "the coordinate reconciliation belongs at the ONE place a foreign coordinate enters (the
            // serve)". So: if the given value is a known ADDRESS, resolve it to its ordinal FIRST; only a
            // value that is not a known address is treated as an ordinal. Addresses are enormous and sparse
            // while ordinals are dense-small, so the two spaces cannot collide in practice — and a value in
            // neither space still answers NOT_INDEXED, never a guess. cons: none — one hash lookup.
            let ordinal = rt.node().da_record_ordinal(ordinal).unwrap_or(ordinal);
            // RAW LANES — the membership family's one wire form (see `digest_to_lane_bytes`): the two
            // accumulators here are wrapping sums whose limbs exceed the field, so the injective 32-byte
            // digest form would silently reduce them. ⛔ §AG class 9 lived here: eight lanes into a
            // literal `[0u8; 32]`, a PANIC on every request (measured 2026-09-13 at this line).
            let limbs_hex = |v: crate::spend_frontier::Digest4| {
                hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&v))
            };
            match rt.node().membership_transition_at(ordinal) {
                Some((before, root, after)) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"ordinal\":{ordinal},\"acc_before_hex\":\"{}\",\
                         \"block_root_hex\":\"{}\",\"acc_after_hex\":\"{}\"}}",
                        limbs_hex(before),
                        limbs_hex(root),
                        limbs_hex(after)
                    ),
                ),
                // This node never folded that ordinal. Answering with a guessed or nearby transition would
                // hand back a carrier start the chain never held, so the spend would build and then be
                // refused with nothing to look at.
                None => (200, format!("{{\"status\":\"REJECTED\",\"reason\":\"NO_TRANSITION\",\"ordinal\":{ordinal}}}")),
            }
        }
        ("POST", "/get_membership_acc") | ("GET", "/get_membership_acc") => {
            // ⭐⭐⭐ O(1) NOTE-MEMBERSHIP TIP — the note-side twin of `/get_nf_unspent_acc`. A spender's
            // `NoteMembershipCarrier` proves `note ∈ block_root` once and folds every later block's root; this
            // serves the endpoint it must land on. FIXED size at ANY chain height: the start accumulator the
            // carrier must be built from, the node's last fold transition `(prev, root)`, and the tip
            // accumulator itself. No stream, no tree, no per-block data.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: every field is a FOLD of already-public block structure — block
            // roots and their running sum. It carries no note, amount, owner, key or count of anything real:
            // the 256-slot shape each root commits is the same whether the block settled payments or not, and
            // the response is identical for every caller (selector-independent, no which-item question).
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (prev, root, acc) = rt.node().membership_tip();
            // RAW LANES — the membership family's one wire form (see `digest_to_lane_bytes`); the same
            // slot width the carried tip uses at the spend-submit gate. ⛔ §AG class 9 lived here: eight
            // lanes into a literal `[0u8; 32]`, a PANIC on every request (measured 2026-09-13 at this
            // line, `range end index 40 out of range for slice of length 32`).
            let limbs_hex = |v: crate::spend_frontier::Digest4| {
                hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&v))
            };
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"genesis_acc_hex\":\"{}\",\"tip_prev_hex\":\"{}\",\"tip_root_hex\":\"{}\",\"acc_hex\":\"{}\"}}",
                    limbs_hex(crate::node::Node::MEMBERSHIP_GENESIS_ACC),
                    limbs_hex(prev),
                    limbs_hex(root),
                    limbs_hex(acc)
                ),
            )
        }
        ("POST", "/get_validator_bond_tree") | ("GET", "/get_validator_bond_tree") => {
            // DIGITAL-CASH PRIVACY: serve the validator COUNT (a network-decentralization metric, not money) but
            // NEVER the AGGREGATE bond — the summed stake is a TVL/supply figure, and a private DAG must leak zero
            // value aggregates. Consensus never needs it served: the finality gadget proves the ≥2/3 bonded-weight
            // threshold in ZERO KNOWLEDGE (the private threshold-cert), and a validator mirrors ITS OWN stake via
            // `/get_validator_bond` (self-lookup by voter_id) — neither of which exposes the total.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let vs = rt.node().validators();
            // `founding_seated`: how many of the launch files' genesis seats (`defi_launch::genesis_seats`, public bytes every
            // node compiles in) still hold a seat. A count of public genesis facts, never a weight or a stake. A rig's checks read
            // their OWN seats as `validators - founding_seated` (A-F100's class: the founding custodian no rig node holds).
            let bonded = vs.bonded_ids();
            let founding = crate::defi_launch::genesis_seats().iter().filter(|(id, _, _, _)| bonded.contains(id)).count();
            (
                200,
                format!("{{\"status\":\"OK\",\"validators\":{},\"founding_seated\":{}}}", vs.len(), founding),
            )
        }
        ("POST", "/path_refresh_stream") => {
            // ⭐ DB-223 Q2 — the PATH-REFRESH STREAM: every completed right window recorded after the wallet's cursor,
            // plus the newest anchor-ring root and the peaks at that step. The same bytes for every wallet at one cursor;
            // it names no note, record or key — only the caller's own last sync point (`since_ordinal`). A request
            // without a cursor is refused: "since genesis" is a different question (the one-shot catch-up), never a
            // default.
            let Some(since) = json_num_field(body, "since_ordinal") else {
                return (200, err_json("BAD_REQUEST:SINCE_ORDINAL"));
            };
            let s = match rt.lock() {
                Ok(g) => g.node().path_refresh_stream(since),
                Err(poisoned) => poisoned.into_inner().node().path_refresh_stream(since),
            };
            let entries: Vec<String> = s
                .entries
                .iter()
                .map(|(o, l, w, r)| {
                    format!(
                        "{{\"ordinal\":{o},\"level\":{l},\"window\":{w},\"root_hex\":\"{}\"}}",
                        hex_encode(&crate::spend_frontier::digest_to_lane_bytes(r))
                    )
                })
                .collect();
            let (newest_ordinal, newest_root_hex) = match s.newest {
                Some((o, r)) => (o, hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&r))),
                None => (0, String::new()),
            };
            let since_root_hex = match s.since_root {
                Some(r) => hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&r)),
                None => String::new(),
            };
            // A-F25: the newest FINAL ring entry and the peaks at that step (the root an object's leg is anchored at);
            // an empty root says this node names none yet. Public chain data, the same for every wallet.
            let (final_ordinal, final_root_hex) = match s.final_anchor {
                Some((o, r)) => (o, hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&r))),
                None => (0, String::new()),
            };
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"catch_up\":{},\"since\":{},\"since_root_hex\":\"{since_root_hex}\",\"newest_ordinal\":{newest_ordinal},\"newest_root_hex\":\"{newest_root_hex}\",\"peaks_hex\":\"{}\",\"final_ordinal\":{final_ordinal},\"final_root_hex\":\"{final_root_hex}\",\"final_peaks_hex\":\"{}\",\"entries\":[{}]}}",
                    s.catch_up,
                    s.since,
                    s.peaks_hex,
                    s.final_peaks_hex,
                    entries.join(",")
                ),
            )
        }
        // ⭐ DB-223 Q2 CATCH-UP — THE WINDOW-INDEX PARAMS (docs/DB-223-Q2-PATH-REFRESH-INDEX-SPEC.md §3–§4): the shards this
        // node serves WHOLE (`/window_index_table`, DB-413) and the chain's PIR seed (the level-major PIR half reads it).
        // DIGITAL-CASH-PRIVACY-REVIEWED: public numbers only; the ask names nothing.
        ("POST", "/window_index_params") | ("GET", "/window_index_params") => {
            let (seed, held, newest) = match rt.lock() {
                Ok(g) => (
                    g.node().window_index_pir_seed(),
                    g.node().window_index().servable_shards(g.node().window_index_folded_blocks()),
                    g.node().path_refresh_stream(u64::MAX).newest.map(|(o, _)| o),
                ),
                Err(poisoned) => {
                    let g = poisoned.into_inner();
                    (
                        g.node().window_index_pir_seed(),
                        g.node().window_index().servable_shards(g.node().window_index_folded_blocks()),
                        g.node().path_refresh_stream(u64::MAX).newest.map(|(o, _)| o),
                    )
                }
            };
            let held_s: Vec<String> = held.iter().map(u64::to_string).collect();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"pir_seed_hex\":\"{}\",\"shard_blocks\":{},\"shard_cols\":{},\"s_rows\":{},\
                     \"n_lwe\":{},\"wave_queries\":{},\"wave_shards\":{},\"newest_ordinal\":{},\"held_shards\":[{}]}}",
                    hex_encode(&seed),
                    crate::window_index::SHARD_BLOCKS,
                    crate::window_index::SHARD_COLS,
                    crate::oli::S_ROWS,
                    crate::oli::N_LWE,
                    crate::oli::WAVE_QUERIES,
                    crate::oli::WAVE_SHARDS,
                    newest.map_or("null".to_string(), |o| o.to_string()),
                    held_s.join(",")
                ),
            )
        }
        // ⭐⭐ DB-413 — THE LOW HALF IS SERVED WHOLE, the §12d rule the level-major tables already obey ("served WHOLE while
        // it is small (no more bytes than a PIR hint)"). A shard table is `SHARD_COLS × S_ROWS` = 256 KB, HALF the 512 KB
        // SimplePIR hint (`S_ROWS × N_LWE × 4`) a wallet fetched for the same shard before any query — so fetching the
        // table outright is fewer bytes than the hint alone, asks nothing per note, and the node computes no 268 M
        // multiply-add hint per ask. Every catching-up wallet fetches every held shard whole, so a fetch names nothing.
        // MEASURED why (sim-20261007-105238 T1.7, seed 0x1): the per-note PIR shape made a catch-up's cost grow with the
        // notes it served (11 queries × 8 KB up per note per shard), so a wallet holding more than 64 wanting notes ran
        // it on a detached thread that a one-command process never waited for — after node 0's restart W1's 98+ restored
        // notes (rewards included) never caught up and its whole 2.3 B read "confirming" on every call. Whole tables make
        // the low catch-up's cost a function of the held shards alone, so it always runs inline.
        // §9.6 (a serve door: no outside bytes enter consensus): 1–4 n/a (reads only; a wrong cell cannot make a spend
        // pass — the wallet keeps only a path that refolds to a ring root it holds); 5. bounded work — one copy of ONE
        // fixed 256 KB table per request, named by a number; 6. parity — the level-major `/window_index_high_table` door
        // (same WHOLE shape, same `TABLE_NOT_HELD`-style refusal for a table with a hole).
        // DIGITAL-CASH-PRIVACY-REVIEWED: the request names a public shard number every catching-up wallet names; the
        // answer is the whole public table — no note, window or cell is ever named. Removes the per-note query COUNT the
        // PIR shape exposed (how many of a wallet's notes were catching up).
        ("POST", "/window_index_table") => {
            let Some(shard) = json_num_field(body, "shard") else {
                return (200, err_json("BAD_REQUEST:SHARD"));
            };
            let (table, version) = {
                let g = match rt.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let version = g.node().window_index_folded_blocks();
                (g.node().window_index().table(shard, version), version)
            };
            match table {
                Some(t) => (
                    200,
                    format!("{{\"status\":\"OK\",\"shard\":{shard},\"version\":{version},\"table_hex\":\"{}\"}}", hex_encode(&t)),
                ),
                None => (200, err_json("SHARD_NOT_HELD")),
            }
        }
        // ⭐⭐ DB-223 Q2 §12d — THE LEVEL-MAJOR HALF OF THE CATCH-UP (docs/DB-223-Q2-PATH-REFRESH-INDEX-SPEC.md §12d).
        // Every level ≥ HIGH_LEVEL is ONE table, asked once per catch-up whatever the note — a constant name.
        // - A small table (≤ WHOLE_MAX_ROOTS, one hint's bytes) is served WHOLE; every wallet fetches every one.
        // - The rest are served by PIR on the OLI layout.
        // - Each table's length, mode and content digest are public (params), so a wallet knows exactly when its cached
        //   hint or table is stale.
        // The §9.6 answers are on `window_index::high_answer`. They move no value (docs/FUNDS-LOSS-KILL-LIST.md §COV).
        // DIGITAL-CASH-PRIVACY-REVIEWED: a request names a LEVEL (every catch-up names every level) and never a note,
        // window or cell; the cell rides only inside the LWE query.
        ("POST", "/window_index_high_params") | ("GET", "/window_index_high_params") => {
            let (tables, seed): (Vec<(usize, usize, Option<Vec<u8>>)>, [u8; 32]) = {
                let g = match rt.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let wi = g.node().window_index();
                (
                    (crate::window_index::HIGH_LEVEL..crate::spend_frontier::SPEND_TREE_DEPTH)
                        .map(|l| (l, wi.high_len(l), wi.high_table(l)))
                        .collect(),
                    g.node().window_index_pir_seed(),
                )
            };
            // The digests are hashed OFF the node lock (up to ~39 MB at 10 years).
            let levels: Vec<String> = tables
                .iter()
                .map(|(l, len, t)| {
                    let mode = match crate::window_index::high_mode(*len) {
                        crate::window_index::HighMode::Whole => "whole",
                        crate::window_index::HighMode::Pir => "pir",
                    };
                    let digest = match t {
                        Some(t) => format!("\"{}\"", hex_encode(blake3::hash(t).as_bytes())),
                        None => "null".to_string(),
                    };
                    format!(
                        "{{\"level\":{l},\"len\":{len},\"mode\":\"{mode}\",\"cols\":{},\"digest_hex\":{digest}}}",
                        crate::window_index::high_cols(*len)
                    )
                })
                .collect();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"pir_seed_hex\":\"{}\",\"high_level\":{},\"whole_max_roots\":{},\"s_rows\":{},\
                     \"n_lwe\":{},\"wave_queries\":{},\"levels\":[{}]}}",
                    hex_encode(&seed),
                    crate::window_index::HIGH_LEVEL,
                    crate::window_index::WHOLE_MAX_ROOTS,
                    crate::oli::S_ROWS,
                    crate::oli::N_LWE,
                    crate::oli::WAVE_QUERIES,
                    levels.join(",")
                ),
            )
        }
        ("POST", "/window_index_high_table") => {
            let Some(level) = json_num_field(body, "level").and_then(|l| usize::try_from(l).ok()) else {
                return (200, err_json("BAD_REQUEST:LEVEL"));
            };
            let (len, table) = {
                let g = match rt.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                (g.node().window_index().high_len(level), g.node().window_index().high_table(level))
            };
            // WHOLE-mode tables only: a PIR-mode table is asked cell-by-cell, never shipped (one shape per mode, and
            // the bandwidth bound of this door is one hint's bytes).
            if crate::window_index::high_mode(len) != crate::window_index::HighMode::Whole {
                return (200, err_json("LEVEL_IS_PIR"));
            }
            match table {
                Some(t) => (200, format!("{{\"status\":\"OK\",\"level\":{level},\"table_hex\":\"{}\"}}", hex_encode(&t))),
                None => (200, err_json("TABLE_NOT_HELD")),
            }
        }
        ("POST", "/window_index_high_hint") => {
            let Some(level) = json_num_field(body, "level").and_then(|l| usize::try_from(l).ok()) else {
                return (200, err_json("BAD_REQUEST:LEVEL"));
            };
            let (len, table, seed) = {
                let g = match rt.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let wi = g.node().window_index();
                (wi.high_len(level), wi.high_table(level), g.node().window_index_pir_seed())
            };
            if crate::window_index::high_mode(len) != crate::window_index::HighMode::Pir {
                return (200, err_json("LEVEL_IS_WHOLE"));
            }
            let Some(table) = table else {
                return (200, err_json("TABLE_NOT_HELD"));
            };
            // ⭐ The hint is extended INCREMENTALLY, off the node lock: one column's work per appended column, and a
            // from-scratch rebuild only when a covered column was rewritten (the digest check inside). A cache, never
            // authority: bounded by the level count (≤ 45 entries of `S_ROWS × N_LWE` words), regenerable from the table.
            static HIGH_HINTS: std::sync::Mutex<std::collections::BTreeMap<usize, crate::window_index::HighHint>> =
                std::sync::Mutex::new(std::collections::BTreeMap::new());
            let prev = match HIGH_HINTS.lock() {
                Ok(m) => m.get(&level).cloned(),
                Err(poisoned) => poisoned.into_inner().get(&level).cloned(),
            };
            let h = crate::window_index::extend_high_hint(prev.as_ref(), &table, &seed);
            // ⛔ DB-405: the VERSION is the root count this hint covers (`len` above); `digest_hex` is its table's
            // `table_digest` (the incremental digest over every covered column, which is the whole table here) — the
            // wallet echoes both on every answer ask.
            let out = format!(
                "{{\"status\":\"OK\",\"level\":{level},\"cols\":{},\"version\":{len},\"digest_hex\":\"{}\",\"hint_hex\":\"{}\"}}",
                h.cols,
                hex_encode(&h.digest),
                hex_encode(&crate::window_index::high_hint_bytes(&h))
            );
            match HIGH_HINTS.lock() {
                Ok(mut m) => {
                    m.insert(level, h);
                }
                Err(poisoned) => {
                    poisoned.into_inner().insert(level, h);
                }
            }
            (200, out)
        }
        ("POST", "/window_index_high_answer") => {
            let (Some(level), Some(cols)) = (
                json_num_field(body, "level").and_then(|l| usize::try_from(l).ok()),
                json_num_field(body, "cols").and_then(|c| usize::try_from(c).ok()),
            ) else {
                return (200, err_json("BAD_REQUEST:LEVEL_OR_COLS"));
            };
            let Some(joined) = json_str_field(body, "queries_hex").and_then(|h| hex_decode(&h)) else {
                return (200, err_json("BAD_REQUEST:QUERIES"));
            };
            let qlen = cols.saturating_mul(4);
            if qlen == 0 || joined.is_empty() || joined.len() % qlen != 0 || joined.len() / qlen > crate::oli::WAVE_QUERIES {
                return (200, err_json("BAD_REQUEST:QUERY_SHAPE"));
            }
            let queries: Vec<Vec<u8>> = joined.chunks(qlen).map(<[u8]>::to_vec).collect();
            let (version, digest) = match versioned_ask(body) {
                Ok(v) => v,
                Err(why) => return (200, err_json(why)),
            };
            let Ok(len) = usize::try_from(version) else {
                return (200, err_json("BAD_REQUEST:VERSION"));
            };
            // ⛔ DB-405: answered over `T_level` AS OF the hint's root count — never the one a later fold extended
            let (held, table) = {
                let g = match rt.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                (g.node().window_index().high_len(level), g.node().window_index().high_table_at(level, len))
            };
            if len > held {
                return (200, err_json("BAD_REQUEST:VERSION_AHEAD"));
            }
            if crate::window_index::high_mode(len) != crate::window_index::HighMode::Pir {
                return (200, err_json("LEVEL_IS_WHOLE"));
            }
            if crate::window_index::high_cols(len) != cols {
                return (200, err_json("BAD_REQUEST:COLS"));
            }
            let Some(table) = table else {
                return (200, err_json("TABLE_NOT_HELD"));
            };
            if crate::window_index::table_digest(&table) != digest {
                return (200, err_json("HINT_STALE"));
            }
            match crate::window_index::high_answer(&table, &queries) {
                Some(answers) => {
                    let mut out = String::with_capacity(answers.len() * crate::oli::S_ROWS * 8);
                    for a in &answers {
                        out.push_str(&hex_encode(a));
                    }
                    (200, format!("{{\"status\":\"OK\",\"answers_hex\":\"{out}\"}}"))
                }
                None => (200, err_json("BAD_REQUEST:QUERY_SHAPE")),
            }
        }
        ("POST", "/validator_id") | ("GET", "/validator_id") => {
            // The node's finality-vote identity — what a wallet bonds onto so this node's votes
            // carry the bond's weight. A pubkey id only: no key material, no amount, no owner.
            // ⛔ A LOCKED identity (its sealed key did not open this run) is never offered: the in-memory stand-in dies at
            // restart, so a bond onto it would be stranded. The wallet stops here, before it spends anything.
            if crate::validator::vote_key_locked() {
                return (200, err_json("VALIDATOR_IDENTITY_LOCKED"));
            }
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.node().own_validator_id() {
                Some(id) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"validator_id_hex\":\"{}\"}}",
                        hex_encode(&id)
                    ),
                ),
                None => (200, err_json("NO_VALIDATOR_KEY")),
            }
        }
        ("POST", "/provision_validator") => {
            // ⭐⭐⭐ THE AUTOMATIC VALIDATOR (user 2026-09-28: bonded nodes "should simply work after bonding not require
            // any extra setup or passwords"). The operator's wallet derives this node's validator identity from its
            // SEED and hands over only the DERIVED keys; the node proves both pairs, never replaces an identity that
            // holds weight, installs, and restarts itself onto it (`validator::provision_identity`, its §9.6 answers).
            // Loopback-only like every route here. DIGITAL-CASH-PRIVACY-REVIEWED: key bytes are never logged; the
            // answer carries the PUBLIC id only.
            let hex = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h));
            let (Some(vote_pk), Some(vote_sk)) = (hex("vote_pk_hex"), hex("vote_sk_hex")) else {
                return (422, err_json("PROVISION_NEEDS_THE_VOTE_KEYPAIR"));
            };
            let outcome = {
                // A poisoned runtime lock is still the node's own state: read through it, as every route here does.
                let guard = match rt.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let n = guard.node();
                crate::validator::provision_identity(&vote_pk, &vote_sk, |vid| {
                    n.validators().bond_of(vid) > 0 || n.validators().is_slashed(vid) || n.pool_holds_bond_onto(vid)
                })
            };
            match outcome {
                Ok(p) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"validator_id_hex\":\"{}\",\"restarting\":{}}}",
                        hex_encode(&crate::pqauth::pubkey_id(&vote_pk)),
                        p == crate::validator::Provision::Installed
                    ),
                ),
                Err(why) => (422, err_json(why)),
            }
        }
        ("GET", "/proof_bits") | ("POST", "/proof_bits") => {
            // Every production proof shape's weakest soundness term under the theorem-backed regime (Johnson bound), scored by the
            // WHIR library's own `soundness.rs` on the numbers this binary builds. Public parameters; computed once per process.
            static REPORT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            let body = REPORT.get_or_init(|| {
                let rows: Vec<String> = usdm_decider::committed_air::proven_bits::report()
                    .into_iter()
                    .map(|(name, bits, term)| format!("{{\"shape\":\"{}\",\"bits\":{bits:.2},\"weakest\":\"{}\"}}", json_escape(&name), json_escape(&term)))
                    .collect();
                format!("{{\"status\":\"OK\",\"shapes\":[{}]}}", rows.join(","))
            });
            (200, body.clone())
        }
        ("GET", "/takeover_cost") | ("POST", "/takeover_cost") => {
            // ⭐ SATOSHI §10 (user ruling 2026-10-05: the takeover cost is SHOWN) — the public figures only: total custody
            // weight, the bottom-2/3 effective security (THORChain's `effectiveSecurityBond`), and the SAT a newcomer must
            // bond to clear the ≥ 2/3 custody tally alone (`2·total`, `quorum_math::least_capturing_weight`). All in SAT base units; the price conversion
            // arrives with increment 4's SAT price. DIGITAL-CASH-PRIVACY-REVIEWED: custody weights are public consensus
            // state; the reserve (confidential, #75) is never read or implied here.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (total, effective, cost) = rt.node().validators().takeover_figures();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"custody_total_sat\":{total},\"effective_security_sat\":{effective},\"takeover_cost_sat\":{cost},\"unit\":\"SAT base units (1e-8 SAT)\"}}"
                ),
            )
        }
        ("GET", "/reward_recipient") | ("POST", "/reward_recipient") => {
            // ⭐ SATOSHI §8.2 — who this node's mining rewards are sealed to (PUBLIC scan key + the next clue index), so the
            // operator's wallet can see whether it is this wallet before it provisions. DIGITAL-CASH-PRIVACY-REVIEWED: the
            // encapsulation key is public by construction (it is in every receive address); the locator key never answers.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.node().reward_recipient() {
                Some(rc) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"provisioned\":true,\"scan_ek_hex\":\"{}\",\"next_index\":{}}}",
                        hex_encode(&rc.scan_ek),
                        rc.next_index
                    ),
                ),
                None => (200, "{\"status\":\"OK\",\"provisioned\":false,\"next_index\":0}".to_string()),
            }
        }
        ("POST", "/set_keep_awake") => {
            // ⭐ §22 7 — the operator's keep-awake consent for this machine (the wallet's one question at "Become a validator",
            // repeated each time it starts this node). Loopback-only like every route here; the node holds the OS keep-awake
            // only while it also holds a custody seat. Moves no value (FUNDS-LOSS-KILL-LIST §COV).
            // DIGITAL-CASH-PRIVACY-REVIEWED: a local power setting; names nothing.
            let on = body.contains("\"on\":true");
            // a poisoned lock still holds this node's runtime as the last writer left it: it is taken as it stands
            let mut rt = match rt.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let (consent, held) = rt.set_keep_awake_consent(on);
            (200, format!("{{\"status\":\"OK\",\"on\":{consent},\"held\":{held}}}"))
        }
        ("POST", "/provision_reward_recipient") => {
            // ⭐ SATOSHI §8.2 — the operator's wallet names where this node's rewards go: its PUBLIC scan key and a locator key
            // for the `"sat"` domain ONLY (never the wallet's `loc_sk`), plus the index the next clue takes (one past the
            // highest `"sat"` index the wallet has seen, so a re-provision after a node rebuild reuses no locator). §9.6
            // answered in the spec §8.2; loopback-only like every route here; no secret is logged; no restart is needed —
            // the recipient is read per produce. DIGITAL-CASH-PRIVACY-REVIEWED: the answer carries the public id only.
            // DB-395: and the wallet's SPEND KEY `spk_hex` (public, 32 bytes): every reward is sealed to it, so this node — which
            // holds every byte it seals — has no spend authority over what it mines.
            let hex = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h));
            let (Some(scan_ek), Some(spk), Some(loc)) = (hex("scan_ek_hex"), hex("spk_hex"), hex("sat_loc_sk_hex")) else {
                return (422, err_json("PROVISION_NEEDS_SCAN_KEY_SPEND_KEY_AND_SAT_LOCATOR_KEY"));
            };
            let Ok(spk) = <[u8; 32]>::try_from(spk.as_slice()) else {
                return (422, err_json("SPEND_KEY_IS_NOT_32_BYTES"));
            };
            let Ok(sat_loc_sk) = <[u8; 32]>::try_from(loc.as_slice()) else {
                return (422, err_json("SAT_LOCATOR_KEY_IS_NOT_32_BYTES"));
            };
            let from_index = json_num_field(body, "from_index").unwrap_or(0);
            match crate::satoshi::provision_reward_recipient_at(&crate::satoshi::reward_recipient_path(), &scan_ek, &spk, sat_loc_sk, from_index) {
                Ok(rc) => {
                    let next = rc.next_index;
                    let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                    g.node_mut().set_reward_recipient(Some(rc));
                    (200, format!("{{\"status\":\"OK\",\"provisioned\":true,\"next_index\":{next}}}"))
                }
                Err(why) => (422, err_json(why)),
            }
        }
        ("POST", "/sign_bond") => {
            // ⭐ DB-313 R2 (b) — THIS NODE CO-SIGNS A BOND ONTO ITS OWN VOTE IDENTITY. Loopback-only like every route
            // here. The wallet names the note it will LOCK and the nullifier it will consume; the node signs
            // `validator_bond_msg(vid, W, locked_cm, nullifier)` with the SAME key `/unbond_validator {own}` signs
            // with, so a bond and its release name ONE identity. Refused while the id is bonded or slashed, or while a
            // bond onto it already waits in this pool: a second would consume its note for no weight.
            let hex32 = |k: &str| {
                json_str_field(body, k).and_then(|h| hex_decode(&h)).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let weight = json_num_field(body, "weight").unwrap_or(0);
            let (Some(locked), Some(nf)) = (hex32("locked_cm_hex"), hex32("nullifier_hex")) else {
                return (422, err_json("SIGN_BOND_NEEDS_LOCKED_CM_AND_NULLIFIER"));
            };
            if weight == 0 {
                return (422, err_json("SIGN_BOND_ZERO_WEIGHT"));
            }
            let (vote_pk, vote_sk) = crate::validator::load_or_create_node_vote_key();
            if crate::validator::vote_key_locked() {
                return (422, err_json("VALIDATOR_IDENTITY_LOCKED"));
            }
            // A bond sits only on an identity the operator can re-derive from the seed. The wallet's bond flow
            // provisions it automatically (`/provision_validator`) before it asks for this signature.
            if !crate::validator::vote_identity_provisioned() {
                return (422, err_json("VALIDATOR_IDENTITY_NOT_SEED_DERIVED"));
            }
            let vid = crate::pqauth::pubkey_id(&vote_pk);
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let n = rt.node();
            if n.validators().bond_of(&vid) > 0 || n.validators().is_slashed(&vid) {
                return (422, err_json("SIGN_BOND_ID_ALREADY_BONDED_OR_SLASHED"));
            }
            if n.pool_holds_bond_onto(&vid) {
                return (422, err_json("SIGN_BOND_ONE_ALREADY_PENDING"));
            }
            let msg = crate::pqauth::validator_bond_msg(&vid, weight, &locked, &nf);
            let Some(sig) = crate::pqauth::ml_dsa_sign(&msg, &vote_sk) else {
                return (500, err_json("SIGN_BOND_KEY_UNREADABLE"));
            };
            let notes = crate::pqauth::bond_statement_encode(&vid, weight, &vote_pk, &sig);
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"validator_id_hex\":\"{}\",\"bond_notes_hex\":\"{}\"}}",
                    hex_encode(&vid),
                    hex_encode(&notes)
                ),
            )
        }
        ("POST", "/get_delegation_targets") | ("GET", "/get_delegation_targets") => {
            // ⭐ §BR-3 17.3 — the ids a SAT delegation can name (live custody seats) and the unseated ids still holding delegated
            // notes, as ONE list: the same bytes for every asker, no amount. A wallet picks a seat from it and matches its own
            // delegated notes' tags (`sat_delegation_tx::delegated_tag(id)`) locally — never a which-note ask.
            // DIGITAL-CASH-PRIVACY-REVIEWED: public consensus state (seated ids are already public by `/get_validator_bond`);
            // no amount, no total, no note is named, and the asker names nothing.
            // The governed unbonding window and the tip's blue score ride along, so the wallet names an epoch-boundary maturity
            // (`sat_delegation_tx::earliest_matures`) the fold accepts; and the bonders' yield index (§17.6) a delegation settles
            // at. DIGITAL-CASH-PRIVACY-REVIEWED: the index is one quarterly aggregate over the public custody total — the same
            // per-quarter figure the §BR-11 miner rate already publishes (no-volume-leak census: no per-block volume or timing).
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let rows: Vec<String> = rt
                .node()
                .validators()
                .delegation_targets()
                .into_iter()
                .map(|(id, seated)| {
                    // F10: each seat's public custody weight (already public per id by `/get_validator_bond`), so the wallet
                    // shows what a delegator joins
                    let bond = rt.node().validators().bond_of(&id);
                    // §22 3: the uptime a delegation to this seat is paid at (public: the chain's record of every seat alike)
                    let (active, windows) = rt.node().delegator_uptime(&id);
                    format!(
                        "{{\"id\":\"{}\",\"seated\":{seated},\"bond\":{bond},\"uptime_active\":{active},\"uptime_windows\":{windows}}}",
                        hex_encode(&id)
                    )
                })
                .collect();
            let tip_blue = rt.node().selected_tip_blue_score().unwrap_or(0);
            // A-F60: the unbonding window and the tip on ONE clock, the chain tick — what a delegation's `matures` names
            let tip_tick = rt.node().chain_tick();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"targets\":[{}],\"unbond_window_ticks\":{},\"tip_tick\":{tip_tick},\"tip_blue_score\":{tip_blue},\"bond_yield_index\":\"{}\"}}",
                    rows.join(","),
                    rt.node().unbond_ticks(),
                    rt.node().peg().bond_yield_index()
                ),
            )
        }
        ("POST", "/get_validator_bond") => {
            // Read a SINGLE validator's bonded weight by its public voter id (H(pubkey)). A per-validator bond is
            // a PUBLIC protocol quantity (the same value `submit_governance_vote` credits), so a wallet can look up
            // ITS OWN row — it holds its ML-DSA pubkey and passes voter_id = H(pubkey) — to mirror its own stake in
            // the Earn screen. No privacy loss (the caller learns only the id it already chose to query); the total
            // is 0 for an unbonded id, so a non-validator simply sees zero.
            let id = json_str_field(body, "voter_id")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            match id {
                Some(id) => {
                    let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
                    // SATOSHI: `bond` stays the id's total VOTING weight (what the chamber shows); `custody_sat` is its SAT
                    // custody weight (what the reserve gates read); `usdm_bond` its finality-only (USDm / membership) weight.
                    let v = rt.node().validators();
                    let (custody, finality) = (v.bond_of(&id), v.finality_weight_of(&id));
                    // §9: the locked note (consensus state, carried whole by the block that seated it) so the bonder's wallet can
                    // open it and re-bond. DIGITAL-CASH-PRIVACY-REVIEWED: public chain data named by a public validator id; the
                    // ciphertext opens only under the bonder's scan key.
                    let locked = rt.node().bond_locked_note(&id).map(hex_encode).unwrap_or_default();
                    // DB-409 + A-F60: the CHAIN TICK from which an unbond releases this bond (`Node::unbond_matures_at`, the
                    // one definition the unbond door and the release judge), `null` when nothing locks it — so the owner
                    // reads when, not just whether; beside it the tip's own tick, on the same clock.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a public bond's anchor plus the governed lock.
                    let matures = rt.node().unbond_matures_at(&id).map_or_else(|| "null".to_string(), |b| b.to_string());
                    let tip_tick = rt.node().chain_tick();
                    let tip_blue = rt.node().selected_tip_blue_score().map_or_else(|| "null".to_string(), |b| b.to_string());
                    // §BR-3 17.6: the id's own-weight yield owed at the chain's index (what its `BondYieldClaim` must state).
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a public seat's own weight × a public quarterly index.
                    let y = rt.node().peg().bond_yield_index();
                    let own_yield = rt.node().own_yield_due(&id, y); // §22 3: weighted by the seat's uptime
                    // ⭐ §22 4 — the status card: the seat's uptime as the chain records it (hours with a deal / hours seated),
                    // whether it is drawn for work this hour, and whether the chain retired it after seven days away.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: public consensus state of a public seat, named by its own id.
                    let act = &rt.node().peg().epoch_keys().activity;
                    let (up_a, up_w) = match act.uptime(&id, act.now) {
                        Some(u) => u,
                        None => (0, 0),
                    };
                    let drawn = act.selected(&id, act.now);
                    let retired = custody == 0 && !locked.is_empty() && !v.is_slashed(&id);
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"bond\":{},\"custody_sat\":{},\"usdm_bond\":{},\"locked_note_hex\":\"{}\",\
                             \"unbond_matures_at_tick\":{matures},\"tip_tick\":{tip_tick},\"tip_blue_score\":{tip_blue},\"own_yield_atomic\":{own_yield},\
                             \"bond_yield_index\":\"{y}\",\"uptime_active\":{up_a},\"uptime_windows\":{up_w},\"drawn\":{drawn},\
                             \"retired\":{retired},\"required_bond_floor\":{}}}",
                            finality,
                            custody,
                            finality.saturating_sub(custody),
                            locked,
                            rt.node().required_bond_floor()
                        ),
                    )
                }
                None => (200, err_json("BAD_VOTER_ID")),
            }
        }
        ("POST", "/get_reserve_swap_address") => {
            // Buy-USDm ATOMIC SWAP — the REAL, threshold-custodied cross-chain deposit address for one swap.
            // BTC (DB-121): a GENUINE BIP341 taproot output whose script path is the k-of-n `OP_CHECKSIGADD`
            // leaf over the LIVE bonded set's custody keys (slots ∝ bond) under a provably-unspendable internal
            // key — a 1-of-1 at the founding validator (deposits work day 1) that GROWS to ⌈2n/3⌉-of-n as more
            // bond (decentralization by construction, NEVER a solo key held off the set, NEVER a fabricated hash —
            // the money-loss failure we refuse). XMR: a GENUINE CryptoNote address over the Ed25519 key-aggregate.
            // FAIL-CLOSED: no bonded validator with registered custody / an unbridged asset ⇒ NO address.
            // DB-123: the address is a function of the swap's MINT BLIND (`d_blind_hex`, the same blind the mint
            // later proves against and seals to every custodian), so each custodian re-derives it at attestation
            // and refuses a deposit at any address the custody script does not control.
            let asset = json_str_field(body, "asset").unwrap_or_default();
            let Some(d_blind) = json_str_field(body, "d_blind_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b))
            else {
                return (200, err_json("BAD_FIELDS"));
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let vs = rt.node().validators();
            let n = vs.bonded_custody().len();
            let group_hex = vs
                .custody_group_commit()
                .map(|g| hex_encode(&g))
                .unwrap_or_default();
            let threshold = vs.custody_threshold();
            // §BR-2: a Bitcoin deposit address is co-signed — it binds the wallet's depositor key (`depositor_x_hex`)
            let depositor = json_str_field(body, "depositor_x_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            let (btc_addr, xmr_addr) = rt.node().reserve_addresses_for_blind(&d_blind, depositor.as_ref());
            drop(rt);
            if n == 0 {
                // No bonded validator has registered custody yet → no threshold reserve key exists → fail-closed.
                (
                    200,
                    "{\"status\":\"OK\",\"reserve_ready\":false,\"reason\":\"no_bonded_quorum\"}"
                        .to_string(),
                )
            } else if asset.eq_ignore_ascii_case("BTC") {
                match btc_addr {
                    Some(addr) => (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"reserve_ready\":true,\"asset\":\"BTC\",\"deposit_address\":\"{}\",\"address_kind\":\"btc-taproot\",\"threshold\":{},\"validators\":{},\"group_commit\":\"{}\"}}",
                            addr, threshold, n, group_hex
                        ),
                    ),
                    None => (200, "{\"status\":\"OK\",\"reserve_ready\":false,\"reason\":\"no_custody_key\"}".to_string()),
                }
            } else if asset.eq_ignore_ascii_case("XMR") {
                // DB-121x: the Monero deposit address is the bonded set's k-of-n multisig wallet (learned from the
                // set's signed announcements — this node needs no Monero wallet to serve it) integrated with a
                // payment id that is a function of the set and the mint blind (DB-123). No known wallet ⇒ no
                // address: an address nothing could spend from would strand the depositor's coin (owner
                // 2026-09-21: "no placeholder addresses… only real derived reserve addresses").
                match xmr_addr {
                    Some(addr) => (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"reserve_ready\":true,\"asset\":\"XMR\",\"deposit_address\":\"{}\",\"address_kind\":\"xmr-integrated\",\"threshold\":{},\"validators\":{},\"group_commit\":\"{}\"}}",
                            addr, threshold, n, group_hex
                        ),
                    ),
                    None => (200, "{\"status\":\"OK\",\"reserve_ready\":false,\"asset\":\"XMR\",\"reason\":\"xmr_custody_not_ready\"}".to_string()),
                }
            } else {
                // Honest fail-closed: only the BTC + XMR bridge endpoints are live. We NEVER fabricate an address
                // for an unbridged asset — a fake here would lose the user's funds.
                let a: String = asset
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .take(8)
                    .collect();
                (200, format!("{{\"status\":\"OK\",\"reserve_ready\":false,\"asset\":\"{}\",\"reason\":\"asset_bridge_pending\"}}", a))
            }
        }
        ("POST", "/get_governance") | ("GET", "/get_governance") => {
            // Bicameral GOVERNANCE read: every open proposal + its running per-chamber tallies + the current
            // tunable params — the wallet renders this LIVE so its Governance view mirrors the chain.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let snap = rt.node().governance_snapshot();
            let dag_width = rt.node().params().dag_width;
            // The LIVE governance-tunable PSM mint collateral ratio (Buy-USDm over-collateralization), read
            // straight from ChainParams so the wallet's Buy quote mirrors a governance retune the instant it enacts.
            let mint_ratio_bps = rt.node().params().mint_ratio_bps;
            // The live GOVERNANCE-TUNABLE POLICY PARAMETERS the wallet mirrors + can propose retunes for (each a
            // ParamChange) — these are protocol CONSTANTS (ratios, lock periods, epoch lengths), never value totals.
            // DIGITAL-CASH PRIVACY: the aggregate stake (`validator_total`), the reserve `bridge_tvl`, and the
            // TVL-derived `required_bond_floor` (= 2×bridge_tvl, zero at zero reserve) are DELIBERATELY NOT served — each is a
            // supply/TVL figure, and serving `2×bridge_tvl` leaks the TVL just as directly as the TVL itself. The #92
            // adaptive-bond floor is still ENFORCED internally at bond time (the node knows its own reserve); it is
            // simply never disclosed to an observer, who must not be able to compute the DAG's total value.
            let p = rt.node().params().clone();
            let mut items = String::new();
            for (i, (id, kind, value, mt, vt)) in snap.iter().enumerate() {
                if i > 0 {
                    items.push(',');
                }
                items.push_str(&format!(
                    "{{\"id\":\"{}\",\"kind\":\"{}\",\"value\":{},\"miner_tally\":{},\"validator_tally\":{}}}",
                    hex_encode(id), kind, value, mt, vt
                ));
            }
            (200, format!(
                "{{\"status\":\"OK\",\"proposals\":[{}],\"dag_width\":{},\"mint_ratio_bps\":{},\
                 \"stake_reward_apr_bps\":{},\"stake_lock_blocks\":{},\"withdraw_fee_min_bps\":{},\"withdraw_fee_max_bps\":{},\
                 \"reward_epoch_blocks\":{},\"bond_tvl_multiple\":{}}}",
                items, dag_width, mint_ratio_bps,
                p.stake_reward_apr_bps, p.stake_lock_blocks, p.withdraw_fee_min_bps, p.withdraw_fee_max_bps,
                p.reward_epoch_blocks, crate::validator::BOND_TVL_MULTIPLE
            ))
        }
        // ⭐ THE CHAIN'S CERTIFIED PRICE MARKS (2026-10-28, hole scanner T1): the wallet's Buy/Cash-out quotes used to fetch
        // mempool.space over clearnet TLS from the user's machine (an IP + interest leak and the one clearnet path in the
        // wallet). The quorum-attested price mark every node applies from the chain (`price_mark_tx`) is the price the mint
        // itself is judged at, so it is the one the wallet shows. Consensus-public data (a validator's public act): no key,
        // no count, no which-item; `price` is USDm-atomic per external atomic unit × `PRICE_SCALE`.
        // ⭐ A-F35 — WHAT A BITCOIN CASH-OUT'S MINER FEE IS RIGHT NOW, for the wallet to show in dollars BEFORE a sale
        // (ADOPTABLE): the legs of a payout share its fee equally (`btc_payout::leg_fee_share`), so the most one piece pays
        // is the fee of a payout it is alone in. `alone_vbytes` is that payout's size under this node's vault's current
        // key; `fee_rate_sat_vb` and `alone_fee_sats` are this node's OWN reading of Bitcoin's fee market, absent (null)
        // on a node with no Bitcoin source. `max_share_divisor`: a piece whose share would pass 1/that of its release
        // waits instead. DIGITAL-CASH-PRIVACY-REVIEWED: no parameter, no account, note, amount or which-item — a size
        // derived from the public key record and a public fee rate; the same answer to every caller.
        ("GET", "/btc_cashout_fee_quote") => {
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let rate = crate::btc_watch::btc_source(crate::bridge::btc_net()).and_then(|s| s.fee_rate_sat_vb());
            let alone = crate::btc_payout::alone_fee_quote(rt.node(), rate.unwrap_or(0));
            let num = |v: Option<u64>| v.map_or("null".to_string(), |x| x.to_string());
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"alone_vbytes\":{},\"fee_rate_sat_vb\":{},\"alone_fee_sats\":{},\"max_share_divisor\":{}}}",
                    num(alone.map(|a| a.0)),
                    num(rate),
                    num(rate.and(alone.map(|a| a.1))),
                    crate::btc_payout::FEE_SHARE_MAX_DIVISOR
                ),
            )
        }
        ("GET", "/price_marks") | ("POST", "/price_marks") => {
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let marks = rt.node().peg().price_mark_census();
            let mut items = String::new();
            for (i, (asset_id, price, epoch)) in marks.iter().enumerate() {
                if i > 0 {
                    items.push(',');
                }
                let coin = crate::bridge_assets::by_psm_ledger(*asset_id);
                let ticker = coin.map_or("", |c| c.ticker);
                // §BR-4: the reference price mints and redemptions are judged at (the 7-day TWAP) and the 30-day low, beside
                // the live mark — public figures of the public marks.
                let peg = rt.node().peg();
                let reference = peg.reference_price(*asset_id).unwrap_or(*price);
                let low = peg.low30(*asset_id).unwrap_or(*price);
                // The same mark in dollars per coin, formed here by the one table's decimals (`bridge_assets`) in integer
                // arithmetic, so no wallet or page carries its own "atoms per coin" and none can be off by a power of ten.
                let usd = coin.and_then(|c| c.micro_dollars_per_coin(*price)).map_or(String::new(), crate::bridge_assets::micro_to_decimal);
                let name = coin.map_or("", |c| c.name);
                items.push_str(&format!("{{\"asset_id\":{asset_id},\"asset\":\"{ticker}\",\"name\":\"{name}\",\"price\":\"{price}\",\"usd\":\"{usd}\",\"epoch\":{epoch},\"reference\":\"{reference}\",\"low30\":\"{low}\"}}"));
            }
            (200, format!("{{\"status\":\"OK\",\"scale\":{},\"marks\":[{}]}}", crate::liquidation::PRICE_SCALE, items))
        }
        ("GET", "/get_signal_status") | ("POST", "/get_signal_status") => {
            // THE SIGNAL FORK — MonerousD's PQ analog of a BTC-Signet signalling chain. Two real mechanisms,
            // both on THIS chain (MoneroUSD integration): (1) SIGNER-GATED finalization — blocks are ratified
            // by the bonded-validator multisig tally, the signet "designated signer" done post-quantum +
            // t-of-n instead of a single classical key; reported as `finalized_height`. (2) FORK SIGNALLING —
            // version-bits-style: every open bicameral governance proposal is a fork/param SIGNAL with its
            // per-chamber vote weights + a state, activating at 2/3 of EACH chamber. DIGITAL-CASH PRIVACY:
            // only per-proposal vote weights + governance-tunable POLICY CONSTANTS (ratios, epoch lengths) are
            // served — NEVER a chamber total / stake / TVL (a value/supply figure). The state derives from the
            // per-proposal weights ALONE (DEFINED = not signalling; STARTED = signalling open).
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (blue_score, finalized_height) = match rt.rpc(RpcRequest::GetInfo) {
                RpcResponse::Info(i) => (i.blue_score, i.finalized_height),
                _ => (0, 0),
            };
            let snap = rt.node().governance_snapshot();
            let p = rt.node().params().clone();
            let mut signals = String::new();
            for (i, (id, kind, value, mt, vt)) in snap.iter().enumerate() {
                if i > 0 {
                    signals.push(',');
                }
                let state = if *mt == 0 && *vt == 0 {
                    "DEFINED"
                } else {
                    "STARTED"
                };
                signals.push_str(&format!(
                    "{{\"id\":\"{}\",\"kind\":\"{}\",\"value\":{},\"miner_tally\":{},\"validator_tally\":{},\"state\":\"{}\"}}",
                    hex_encode(id), kind, value, mt, vt, state
                ));
            }
            let n = snap.len();
            drop(rt);
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"network\":\"monerousd\",\"model\":\"pq-signet-bicameral\",\
                     \"signer\":\"bonded-validator multisig tally — signet-style block finalization\",\
                     \"activation_rule\":\"2/3 of EACH chamber (miner + validator)\",\
                     \"height\":{blue_score},\"finalized_height\":{finalized_height},\
                     \"active_params\":{{\"dag_width\":{},\"mint_ratio_bps\":{},\"stake_reward_apr_bps\":{},\"stake_lock_blocks\":{},\"reward_epoch_blocks\":{}}},\
                     \"signal_count\":{n},\"signals\":[{signals}]}}",
                    p.dag_width, p.mint_ratio_bps, p.stake_reward_apr_bps, p.stake_lock_blocks, p.reward_epoch_blocks
                ),
            )
        }
        ("POST", "/propose_param_change") => {
            // Permissionless PROPOSE of a runtime-tunable parameter change. The BICAMERAL anti-capture gate is
            // at ENACT (2/3 of BOTH chambers); the CONSTITUTIONAL gate (never exclusionary / less private / less
            // secure) is enforced at BOTH propose (rejected right here) AND enact — so an unconstitutional change
            // can never open or apply. `value` is sent as a string for JSON-number safety. Idempotent per change.
            let kind = json_str_field(body, "kind").unwrap_or_default();
            let value: u64 = json_str_field(body, "value")
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            // ONE reconstruction shared with the gossip path (no divergence): unknown kind → None (fail-closed).
            let change = crate::governance::ParamChange::from_kind_value(&kind, value);
            match change {
                Some(c) => {
                    let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
                    match rt.governance_propose(c) {
                        Ok(id) => (
                            200,
                            format!("{{\"status\":\"OK\",\"proposal_id\":\"{}\"}}", hex_encode(id.as_bytes())),
                        ),
                        // Rejected at the proposal layer — the change would weaken the protocol. Surfaced honestly.
                        Err(v) => (
                            200,
                            format!(
                                "{{\"status\":\"REJECTED\",\"reason\":\"UNCONSTITUTIONAL\",\"detail\":\"{}\"}}",
                                v
                            ),
                        ),
                    }
                }
                None => (200, err_json("UNKNOWN_PARAM")),
            }
        }
        ("POST", "/submit_governance_vote") => {
            // SOUND validator-chamber vote: the voter signs `governance_vote_msg(proposal_id, chamber=2)` with
            // its ML-DSA spend key; the node VERIFIES that signature, sets the voter id = H(pubkey), and credits
            // the voter's on-chain bonded weight (0 if not a validator). So no party can cast another's vote and
            // no one can inflate their weight. Then it tries to enact (miner chamber = 0 → never enacts alone).
            let pid = json_str_field(body, "proposal_id")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            let pubkey = json_str_field(body, "voter_pubkey")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let sig = json_str_field(body, "sig")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            match pid {
                Some(pid) => {
                    // The runtime runs the SINGLE authenticated adopt shared with the gossip path: verify the
                    // ML-DSA sig over governance_vote_msg(id,2) → voter id = H(pubkey) → credit the LIVE bonded
                    // weight → record → try-enact → GOSSIP on a tally change so the vote converges mesh-wide.
                    // None ⇒ bad signature (fail-closed). Then the vote directory replicates like every other.
                    let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
                    match rt.governance_adopt_vote_by_id(&crate::hash::Hash32(pid), &pubkey, &sig) {
                        Some((recorded, weight)) => (
                            200,
                            format!(
                                "{{\"status\":\"OK\",\"recorded\":{recorded},\"weight\":{weight}}}"
                            ),
                        ),
                        None => (200, err_json("BAD_VOTE_SIG")),
                    }
                }
                None => (200, err_json("BAD_PROPOSAL_ID")),
            }
        }
        ("POST", "/register_username") => {
            // ⛔ AUDIT F9 (2026-11-10): this route wrote the gossip registry, where a name belonged to whoever reached
            // each node first. A name is claimed on the chain: sign a directory entry and post it to `/dir/register`;
            // a block carries it and every node applies it in one order. Nothing is registered here.
            (200, err_json("MOVED_TO_DIR_REGISTER"))
        }
        ("POST", "/resolve_username") | ("GET", "/resolve_username") => {
            // Resolve `@name` → its current address ON THE CHAIN (the same read as `/dir/resolve`; audit F9). `address`
            // is null if unregistered.
            let name = json_str_field(body, "name").unwrap_or_default();
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.node().resolve_name(&name) {
                Some(addr) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"address\":\"{}\"}}",
                        json_escape(addr)
                    ),
                ),
                None => (200, "{\"status\":\"OK\",\"address\":null}".to_string()),
            }
        }
        ("POST", "/names_of") | ("GET", "/names_of") => {
            // Public REVERSE lookup: all @names pointing at `address`. Lets a wallet re-discover ITS OWN handles
            // after a restart (restart-proof, no local persistence). Public directory data — no privacy loss.
            let address = json_str_field(body, "address").unwrap_or_default();
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let names = rt.node().names_of(&address);
            let arr = names
                .iter()
                .map(|n| format!("\"{}\"", json_escape(n)))
                .collect::<Vec<_>>()
                .join(",");
            (200, format!("{{\"status\":\"OK\",\"names\":[{}]}}", arr))
        }
        // ⛔ AUDIT F15 (2026-11-10) — THE UNPAID SIGN-UP ROUTES ARE CLOSED. They queued an entry on its signature alone and
        // every node kept it for ever, at no cost and with no size bound. An entry is published by `/dir/submit` below, as
        // an object that pays for its bytes. A wallet that still calls these is told so in words it can show.
        ("POST", "/dir/register") | ("POST", "/group/register") => (
            200,
            "{\"status\":\"OK\",\"queued\":false,\"reason\":\"PAID_ENTRY_REQUIRED\",\"detail\":\"A directory entry is published as a paid entry (POST /dir/submit). Update the wallet.\"}".to_string(),
        ),
        // ⭐ AUDIT F15 — publish a PAID directory entry the wallet built (`dir_entry_tx::DirEntryTx`, framed): the signed
        // entry and the USDm burn that pays for the bytes every node will keep. The route only publishes; the entry is in
        // the directory when a block carries the object and every node applies it at that block's fold.
        // §9.6 for this ingress: (1) PoW is the carrying block's; (2) the entry's ML-DSA signature and binding, the burn's
        // carrier and its note's membership are verified by `Node::publish_dir_entry` (Admit) and again at the fold; (3) no
        // value is created: the burn destroys the price; (4) a repeat is refused by the fee note's nullifier in the spent
        // set; (5) the object is bounded at decode (`DIR_ENTRY_BYTES_MAX` and the carrier's fixed shapes) before any verify;
        // (6) parity with `/submit_dsol_deploy`: the same decode-then-publish, the same answers.
        // (7) scale: one request, one pooled object of bounded size; nothing per bonded node; the same cost at any height.
        ("POST", "/dir/submit") => {
            let parsed = json_str_field(body, "object_hex")
                .and_then(|h| hex_decode(&h))
                .and_then(|b| match crate::chain_object::unframe(&b) {
                    Some((crate::chain_object::Class::DirEntry, p)) => crate::dir_entry_tx::DirEntryTx::decode(p),
                    _ => None,
                });
            let Some(t) = parsed else {
                return (400, err_json("MALFORMED_DIR_ENTRY"));
            };
            let price = t.price();
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_dir_entry(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    format!("{{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"queued\":true,\"price_atomic\":{price},\"detail\":\"The entry was admitted to the pool and will travel. It is in the directory when a block carries it.\"}}"),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"DIR_ENTRY_REFUSED\",\"queued\":false,\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/dir/profile") | ("GET", "/dir/profile") => {
            // Resolve an ADDRESS → its published profile (display, bio, DM fee) — data the owner CHOSE to
            // publish on the directory carrier, exactly like an @username. One indexed read.
            let addr = match json_str_field(body, "address") {
                Some(a) if !a.is_empty() => a,
                _ => return (200, err_json("MISSING_ADDRESS")),
            };
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            match rt.node().resolve_dir_profile(&addr) {
                Some(p) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"display\":{},\"bio\":{},\"fee_micro\":{},\"avatar\":{}}}",
                        serde_json::to_string(&p.display).unwrap_or_else(|_| "\"\"".into()),
                        serde_json::to_string(&p.bio).unwrap_or_else(|_| "\"\"".into()),
                        p.fee_micro,
                        serde_json::to_string(&p.avatar).unwrap_or_else(|_| "\"\"".into())
                    ),
                ),
                None => (200, "{\"status\":\"OK\",\"display\":null}".to_string()),
            }
        }
        ("POST", "/dir/resolve") | ("GET", "/dir/resolve") => {
            // Resolve `@name` → its current ON-CHAIN address in one indexed read; `address` is null if unregistered.
            let name = match json_str_field(body, "name") {
                Some(s) => s,
                None => String::new(),
            };
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            match rt.node().resolve_dir_name(&name) {
                Some(addr) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"address\":\"{}\"}}",
                        json_escape(addr)
                    ),
                ),
                None => (200, "{\"status\":\"OK\",\"address\":null}".to_string()),
            }
        }
        ("POST", "/group/resolve") | ("GET", "/group/resolve") => {
            // Resolve a group `@handle` → its on-chain record (owner address for a join request) in one indexed read.
            let handle = match json_str_field(body, "handle") {
                Some(s) => s,
                None => String::new(),
            };
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            match rt.node().resolve_dir_group(&handle) {
                Some(g) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"handle\":\"{}\",\"name\":\"{}\",\"topic\":\"{}\",\"owner_addr\":\"{}\"}}",
                        json_escape(&g.handle),
                        json_escape(&g.name),
                        json_escape(&g.topic),
                        json_escape(&g.owner_addr)
                    ),
                ),
                None => (200, "{\"status\":\"OK\",\"owner_addr\":null}".to_string()),
            }
        }
        // ⭐ SPEC §12.6 — THE MARKETPLACE'S READS. Each is a keyed read, or an index range, of THIS node's own copy of the
        // directory every node folds from the chain: nothing is asked of anyone else, so nobody learns what a wallet
        // holds or looks at. What they serve is what creators chose to publish (an asset's name and picture, a
        // collection's title and cover): never a holder, a balance, a sale or a count of trades.
        // A page is an index range of the apply order (`from`/`skip` and `max`, at most [`DIR_READ_PAGE_MAX`] rows), the
        // refill door's own shape; a reader that wants more asks for the next range.
        ("POST", "/dir/asset") | ("GET", "/dir/asset") => {
            // by the asset's id (64 hex), or by the tag its notes carry (48 hex): a wallet holds notes by tag
            let id = json_str_field(body, "id").unwrap_or_default();
            let tag = json_str_field(body, "tag").unwrap_or_default();
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let found = if id.is_empty() { rt.node().resolve_dir_asset_by_tag(&tag) } else { rt.node().resolve_dir_asset(&id) };
            match found {
                Some(a) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"found\":true,\"id\":\"{}\",\"tag\":\"{}\",\"kind\":\"{}\",\"symbol\":\"{}\",\"name\":\"{}\",\"creator\":\"{}\",\"logo\":\"{}\",\"collection\":\"{}\",\"has_art\":{},\"supply\":{}}}",
                        hex_encode(&a.id),
                        hex_encode(&crate::directory::asset_tag_bytes(&a.id)),
                        if a.nft { "nft" } else { "token" },
                        json_escape(&a.symbol),
                        json_escape(&a.name),
                        hex_encode(&a.creator),
                        hex_encode(&a.logo),
                        json_escape(&a.collection),
                        a.pic.is_some(),
                        a.supply.map_or_else(|| "null".to_string(), |v| format!("\"{v}\""))
                    ),
                ),
                None => {
                    // IonSwap pools: a tag no asset record names may be a pool's SHARE notes (a share is a note of the
                    // pool's own tag, never a directory entry). This node's pools cache names the pool; the answer says
                    // it is a share and of which token's pool, so a wallet shows "X-USDm pool shares", not a bare tag.
                    // A LOCKED share (spec §14) is named the same way, with the Monday it unlocks on: the wallet needs the week to
                    // build its removal, an unlock or an extension, and shows the date.
                    let share = hex_decode(&tag.to_lowercase()).and_then(|b| <[u8; 24]>::try_from(b.as_slice()).ok()).and_then(|t| rt.node().ion_cache().share_of_tag(&t));
                    match share {
                        Some((token, week)) => {
                            let of = rt.node().resolve_dir_asset(&hex_encode(&token));
                            let sym = of.map(|a| a.symbol.clone()).unwrap_or_default();
                            let sym = if sym.is_empty() { "pool".to_string() } else { sym };
                            let (kind, symbol, name) = if week == 0 {
                                ("pool_share", format!("{sym}-USDm LP"), format!("Your part of the {sym} pool (hand it back on the Pools page for both assets)"))
                            } else {
                                (
                                    "pool_share_locked",
                                    format!("{sym}-USDm LP (locked)"),
                                    format!("Your part of the {sym} pool, locked: it can be taken out from the unlock date on, and earns fees until then"),
                                )
                            };
                            (
                                200,
                                format!(
                                    "{{\"status\":\"OK\",\"found\":true,\"id\":\"\",\"tag\":\"{}\",\"kind\":\"{kind}\",\"symbol\":\"{}\",\"name\":\"{}\",\"pool_token\":\"{}\",\"lock_week\":{week},\"unlock_secs\":{},\"creator\":\"\",\"logo\":\"\",\"collection\":\"\",\"has_art\":false}}",
                                    tag.to_lowercase(),
                                    json_escape(&symbol),
                                    json_escape(&name),
                                    hex_encode(&token),
                                    if week == 0 { 0 } else { crate::ion_pool_tx::lock_week_start_secs(week) }
                                ),
                            )
                        }
                        None => (200, "{\"status\":\"OK\",\"found\":false}".to_string()),
                    }
                }
            }
        }
        ("POST", "/dir/asset_art") | ("GET", "/dir/asset_art") => {
            let id = json_str_field(body, "id").unwrap_or_default();
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let art = rt.node().dir_asset_art(&id);
            match crate::directory::art_mime(art) {
                Some(mime) => (200, format!("{{\"status\":\"OK\",\"found\":true,\"mime\":\"{mime}\",\"art_hex\":\"{}\"}}", hex_encode(art))),
                None => (200, "{\"status\":\"OK\",\"found\":false}".to_string()),
            }
        }
        ("POST", "/dir/collection") | ("GET", "/dir/collection") => {
            let handle = json_str_field(body, "handle").unwrap_or_default();
            let from = json_num_field(body, "from").and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
            let max = dir_read_page_len(json_num_field(body, "max"));
            let with_cover = json_bool_field(body, "cover").unwrap_or(false);
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = rt.node();
            match node.resolve_dir_collection(&handle) {
                Some(c) => {
                    let (pieces, total) = node.dir_collection_pieces_page(&handle, from, max);
                    let ids: Vec<String> = pieces.iter().map(|p| format!("\"{}\"", hex_encode(p))).collect();
                    let cover = node.dir_collection_cover(&handle);
                    let cover_json = match (with_cover, crate::directory::art_mime(cover)) {
                        (true, Some(mime)) => format!(",\"cover_mime\":\"{mime}\",\"cover_hex\":\"{}\"", hex_encode(cover)),
                        _ => String::new(),
                    };
                    (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"found\":true,\"handle\":\"{}\",\"title\":\"{}\",\"text\":\"{}\",\"owner\":\"{}\",\"has_cover\":{},\"total\":{total},\"from\":{from},\"pieces\":[{}]{cover_json}}}",
                            json_escape(&c.handle),
                            json_escape(&c.title),
                            json_escape(&c.text),
                            hex_encode(&c.owner),
                            !cover.is_empty(),
                            ids.join(",")
                        ),
                    )
                }
                None => (200, "{\"status\":\"OK\",\"found\":false}".to_string()),
            }
        }
        ("POST", "/dir/collections") | ("GET", "/dir/collections") => {
            let skip = json_num_field(body, "skip").and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
            let max = dir_read_page_len(json_num_field(body, "max"));
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = rt.node();
            let (page, total) = node.dir_collections_page(skip, max);
            let rows: Vec<String> = page
                .iter()
                .map(|c| {
                    format!(
                        "{{\"handle\":\"{}\",\"title\":\"{}\",\"text\":\"{}\",\"owner\":\"{}\",\"pieces\":{},\"has_cover\":{}}}",
                        json_escape(&c.handle),
                        json_escape(&c.title),
                        json_escape(&c.text),
                        hex_encode(&c.owner),
                        c.pieces.len(),
                        !node.dir_collection_cover(&c.handle).is_empty()
                    )
                })
                .collect();
            (200, format!("{{\"status\":\"OK\",\"total\":{total},\"skip\":{skip},\"collections\":[{}]}}", rows.join(",")))
        }
        // ⭐ ONE PAGE OF THE DIRECTORY'S APPLY-ORDER LOG — the explorer's list of tokens, NFTs and @names, newest first by
        // cursor. The same entries the refill door serves every peer (`Node::dir_log_page`), with LESS in them: no
        // signature, no key, and no address at all. A profile (keyed by an address) and a group answer with their kind
        // alone, so a page never lists who published what or where a name points. A read, not a door: nothing is
        // admitted, and a page is at most `DIR_READ_PAGE_MAX` rows of bounded entries whatever the directory holds.
        ("POST", "/dir/log") | ("GET", "/dir/log") => {
            let from = json_num_field(body, "from").unwrap_or(0);
            let max = dir_read_page_len(json_num_field(body, "max"));
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = rt.node();
            let total = node.dir_log_len();
            let rows: Vec<String> = node
                .dir_log_page(from, max)
                .iter()
                .enumerate()
                .map(|(n, e)| {
                    let i = from.saturating_add(n as u64);
                    use crate::directory::{KIND_GROUP, KIND_NAME_TRANSFER, KIND_PROFILE};
                    if e.kind == KIND_PROFILE || e.kind == KIND_GROUP {
                        return format!("{{\"i\":{i},\"kind\":{}}}", e.kind);
                    }
                    // a hand-over's `name` is the new owner's id: served, it would link every name one key holds
                    let name = if e.kind == KIND_NAME_TRANSFER { "" } else { e.name.as_str() };
                    format!(
                        "{{\"i\":{i},\"kind\":{},\"key\":\"{}\",\"name\":\"{}\",\"topic\":\"{}\",\"pic\":{}}}",
                        e.kind,
                        json_escape(&e.key),
                        json_escape(name),
                        json_escape(&e.topic),
                        e.pic.is_some()
                    )
                })
                .collect();
            (200, format!("{{\"status\":\"OK\",\"total\":{total},\"from\":{from},\"entries\":[{}]}}", rows.join(",")))
        }
        // ── IONSWAP POOLS (lane goods, 2026-11-11; `ion_pool_tx`). These read THIS node's own copy of the pools' rows (the
        // chain keeps only a root). What a row holds is public by the pool's own rule: its two balances, its share count
        // and its price, once a batch. No route here names a wallet, a note or an order's owner.
        ("POST", "/ion/pools") | ("GET", "/ion/pools") => {
            // every pool, the deepest first; `q` narrows by symbol, name or the start of the token's id
            let q = json_str_field(body, "q").unwrap_or_default().trim().to_lowercase();
            let skip = json_num_field(body, "skip").and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
            let max = dir_read_page_len(json_num_field(body, "max"));
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = rt.node();
            if !node.ion_cache_is_current() {
                // a node that joined by a certified state, or restarted, before its copy is refilled: said, never guessed
                return (200, format!("{{\"status\":\"OK\",\"ready\":false,\"total\":0,\"pools\":[],{}}}", ion_fees_json()));
            }
            // SAFE AT SCALE: the cache keeps its rows in liquidity order (`IonCache::ranked`), so a page of the top pools
            // reads `skip + max` rows and resolves the names of that page alone, whatever the chain holds. A SEARCH reads
            // every pool's name once (a term that grows with the pools; a search is a person's act, never a tick's).
            let named = |r: &crate::ion_pool_tx::IonRow| {
                let a = node.resolve_dir_asset(&hex_encode(&r.token));
                (a.as_ref().map(|a| a.symbol.clone()).unwrap_or_default(), a.as_ref().map(|a| a.name.clone()).unwrap_or_default())
            };
            // the lock status every row reads is at THIS node's chain clock (the median time past of its selected tip)
            let now_week = crate::ion_pool_tx::lock_week_of(node.chain_time_ms() / 1_000);
            let supply_of = |r: &crate::ion_pool_tx::IonRow| node.resolve_dir_asset(&hex_encode(&r.token)).and_then(|a| a.supply);
            let (total, page): (usize, Vec<String>) = if q.is_empty() {
                let page = node.ion_cache().ranked().skip(skip).take(max).map(|r| { let (symbol, name) = named(r); ion_row_json(r, &symbol, &name, false, now_week, supply_of(r)) }).collect();
                (usize::try_from(node.ion_cache().rows_held()).unwrap_or(usize::MAX), page)
            } else {
                let hits: Vec<(&crate::ion_pool_tx::IonRow, String, String)> = node
                    .ion_cache()
                    .ranked()
                    .map(|r| { let (symbol, name) = named(r); (r, symbol, name) })
                    .filter(|(r, symbol, name)| hex_encode(&r.token).starts_with(&q) || symbol.to_lowercase().contains(&q) || name.to_lowercase().contains(&q))
                    .collect();
                (hits.len(), hits.iter().skip(skip).take(max).map(|(r, symbol, name)| ion_row_json(r, symbol, name, false, now_week, supply_of(r))).collect())
            };
            (200, format!("{{\"status\":\"OK\",\"ready\":true,\"total\":{total},\"skip\":{skip},\"pools\":[{}],{}}}", page.join(","), ion_fees_json()))
        }
        ("POST", "/ion/pool") | ("GET", "/ion/pool") => {
            // one pool by its token's id: its row with the whole price ring, and how many of its orders wait for a batch
            let Some(token) = json_str_field(body, "token").and_then(|h| hex_decode(&h)).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) else {
                return (400, err_json("MALFORMED_TOKEN"));
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = rt.node();
            if !node.ion_cache_is_current() {
                return (200, format!("{{\"status\":\"OK\",\"ready\":false,\"found\":false,{}}}", ion_fees_json()));
            }
            let pending = node.peg().ion_pending().iter().filter(|o| o.token == token).count();
            match node.ion_cache().row(&token) {
                Some(r) => {
                    let a = node.resolve_dir_asset(&hex_encode(&token));
                    let now_week = crate::ion_pool_tx::lock_week_of(node.chain_time_ms() / 1_000);
                    let row = ion_row_json(r, &a.as_ref().map(|a| a.symbol.clone()).unwrap_or_default(), &a.as_ref().map(|a| a.name.clone()).unwrap_or_default(), true, now_week, a.as_ref().and_then(|a| a.supply));
                    (200, format!("{{\"status\":\"OK\",\"ready\":true,\"found\":true,\"pending\":{pending},\"pool\":{row},{}}}", ion_fees_json()))
                }
                None => (200, format!("{{\"status\":\"OK\",\"ready\":true,\"found\":false,\"pending\":{pending},{}}}", ion_fees_json())),
            }
        }
        ("POST", "/submit_ion_order") => {
            // CHAIN-PUBLISH-REVIEWED: a wire-field parser plus `Node::publish_ion_order`, which pools the framed
            // `Class::IonOrder` object after the fold's own verdict at the Admit door; the order's burns ride that
            // transaction's nullifier lane, so they travel to every node. Fail-closed on a malformed body (400).
            let Some(t) = json_str_field(body, "order_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::ion_pool_tx::IonOrderTx::decode(&b)) else {
                return (400, err_json("MALFORMED_ION_ORDER"));
            };
            let outcome = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().publish_ion_order(&t)
            };
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"order_id\":\"{}\",\"detail\":\"The order was admitted to the pool and will travel. It is paid by the batch after the block that carries it.\"}}",
                        hex_encode(&t.id())
                    ),
                ),
                A::Refused(why) if why == crate::asset_tx::ASSET_SPEND_PENDING => asset_pending_answer(),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"ION_ORDER_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/register_clue_key") => {
            // Publish the caller's PUBLIC OMR clue key for oblivious cold-restore. Authenticated by an ML-DSA
            // signature over `clue_register_msg(clue_pk)`; the node keys it by H(pubkey) = the address `b`, so
            // only the address owner can set their OWN clue key. The clue key is public (it cannot decrypt).
            let pubkey = json_str_field(body, "pubkey")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let clue_pk = json_str_field(body, "clue_pk")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let sig = json_str_field(body, "sig")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            if clue_pk.is_empty() {
                return (200, err_json("MISSING_CLUE_PK"));
            }
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // `registered` = the ML-DSA signature authenticated (Some(_)); an identical re-publish is still a
            // success (Some(false)). Only a genuinely-changed registration is gossiped onward (inside register_clue).
            let ok = rt.register_clue(pubkey, clue_pk, sig).is_some();
            (200, format!("{{\"status\":\"OK\",\"registered\":{ok}}}"))
        }
        ("POST", "/resolve_clue_key") | ("GET", "/resolve_clue_key") => {
            // Resolve an address owner's PUBLIC clue key by `b = H(spend_pk)` (a sender reads `b` from the
            // recipient's address, then attaches a detection clue to the note it sends). null if unpublished.
            let b_bytes = json_str_field(body, "b_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            if b_bytes.len() != 32 {
                return (200, err_json("BAD_OWNER_ID"));
            }
            let mut owner = [0u8; 32];
            owner.copy_from_slice(&b_bytes);
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.node().resolve_clue(&owner) {
                Some(pk) => (
                    200,
                    format!("{{\"status\":\"OK\",\"clue_pk\":\"{}\"}}", hex_encode(pk)),
                ),
                None => (200, "{\"status\":\"OK\",\"clue_pk\":null}".to_string()),
            }
        }
        ("POST", "/get_note_clues") | ("GET", "/get_note_clues") => {
            // Batch-resolve per-note detection clues by commitment (oblivious cold-restore). Input `cms_hex` =
            // concat of 32-byte note_cms; output `clues` = array of clue hex (or null) in the SAME order. The
            // wallet fetches note ciphertexts (/get_pq_notes), extracts each public cm (first 32 B), batch-
            // resolves clues here, then tests the CHEAP clue before the expensive ML-KEM decap → O(owned) decaps.
            let cms = json_str_field(body, "cms_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let mut arr = String::from("[");
            let mut off = 0;
            let mut first = true;
            while off + 32 <= cms.len() {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&cms[off..off + 32]);
                off += 32;
                if !first {
                    arr.push(',');
                }
                first = false;
                match rt.note_clue(&cm) {
                    Some(clue) => arr.push_str(&format!("\"{}\"", hex_encode(&clue))),
                    None => arr.push_str("null"),
                }
            }
            arr.push(']');
            (200, format!("{{\"status\":\"OK\",\"clues\":{}}}", arr))
        }
        ("POST", "/da_record") | ("GET", "/da_record") => {
            // ONE record, by its canonical address. This is the by-id access the instant restore uses: the
            // account bucket names (address, slot), so a wallet fetches exactly the record holding its note
            // and never walks a range. Constant response — the full 256-slot cover shape, reals and cover
            // alike — so which slot mattered is not observable, and an unrecorded address answers nothing.
            // ⭐ DB-223 Q2 §11 (a): `ordinal` names the record by FOLD ORDINAL (NOT-AN-ADDRESS) — the coordinate an
            // OLI entry carries. It resolves through `da_addr_at_ordinal` ONLY and the reply names the
            // `record_addr` it resolved to, so a reader keys the strip and the position by the address, never by
            // the ordinal; an ordinal this node has not folded answers nothing and names no address. A request
            // naming NEITHER coordinate is refused by name — it was read as address 0 (no caller relied on it:
            // grep of both crates and scripts finds no `/da_record` client).
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(ordinal) = json_num_field(body, "ordinal") {
                let resolved = rt
                    .node()
                    .da_addr_at_ordinal(ordinal)
                    .and_then(|a| rt.node().da_record_notes(a).map(|b| (a, b)));
                return match resolved {
                    Some((a, blob)) => (
                        200,
                        format!("{{\"status\":\"OK\",\"record_addr\":{a},\"notes_hex\":\"{}\"}}", hex_encode(&blob)),
                    ),
                    None => (200, "{\"status\":\"OK\",\"notes_hex\":\"\"}".to_string()),
                };
            }
            let Some(addr) = json_num_field(body, "addr") else {
                return (400, "{\"status\":\"ERROR\",\"error\":\"DA_RECORD_NAMES_NO_RECORD\"}".to_string());
            };
            // The record's FOLD ORDINAL rides beside its notes (`null` while it has not folded): a wallet holding a note's
            // filed position — a record ADDRESS, the coordinate `da_pos` and the spend witness read — needs the ordinal to
            // place its path, and must never read the address as one. MEASURED 2026-10-06 (`sim-20261006-043004`, T1.4):
            // the wallet's book posted `{"ordinal": 172109173502353808}` — an address — and the node served nothing.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a record's ordinal is public chain structure, answered for the record named.
            let ordinal = rt.node().da_record_ordinal(addr).map_or("null".to_string(), |o| o.to_string());
            match rt.node().da_record_notes(addr) {
                Some(blob) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"record_addr\":{addr},\"ordinal\":{ordinal},\"notes_hex\":\"{}\"}}",
                        hex_encode(&blob)
                    ),
                ),
                None => (200, format!("{{\"status\":\"OK\",\"notes_hex\":\"\"}}")),
            }
        }
        ("POST", "/note_copath") | ("GET", "/note_copath") => {
            // A note's in-block membership path, DERIVED from the DA layer (its block's real notes plus the
            // deterministic cover), never read from a stored witness and never requiring the requester to
            // have watched a window. Replaces the wallet paging the whole note stream to rebuild the same
            // path — that walk grew with the chain and could only succeed while the blocks were still served.
            //
            // Positions arrive as a batch of `seq(8) ‖ slot(1)`; the caller cover-pads the batch to a
            // CONSTANT size, so which position is real is not observable here. Selector-independent: the same
            // position returns the same bytes to everyone, and the answer is self-verifying — a copath that
            // does not refold to the returned block root is rejected by the caller, so nothing is trusted.
            let raw = json_str_field(body, "positions_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐⭐⭐ RESOLVE BY NOTE COMMITMENT — the only coordinate that means the same thing everywhere.
            //
            // A caller may name its note by `cms_hex` instead of by a stored position. That matters because
            // the position an account bucket files is produced by `record_note_payload`, and the faucet/send
            // path calls the HEIGHT-addressed variant — whose own doc comment says "a record addressed by
            // height collides across nodes" (many blocks share a blue_score in a DAG). Measured live: 7 of 7
            // sampled positions named DIFFERENT blocks on two peered nodes. A recipient reading such a
            // position from its bucket then asks its own node to resolve it and gets the wrong record, so the
            // payment settles on chain and stays invisible to its owner.
            //
            // The note COMMITMENT has no such problem: `da_seq_at_note_cm` is a written-down cm -> address
            // index every node builds from the same replicated records, so each node resolves the same note
            // to ITS OWN correct local address. This is the Bitcoin/Kaspa property — identify the thing by
            // what it IS, never by where this node happened to put it.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: the caller cover-pads its cm batch to a CONSTANT count exactly as
            // it does for positions, so which entry is real is not observable, and the answer is identical for
            // every caller asking about the same cm (selector-independent).
            let cms: Vec<[u8; 32]> = json_str_field(body, "cms_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default()
                .chunks_exact(32)
                .map(|c| {
                    let mut w = [0u8; 32];
                    w.copy_from_slice(c);
                    w
                })
                .collect();
            let mut raw = raw;
            if !cms.is_empty() {
                // Rebuild the position list from the commitments this node can place. A cm this node has no
                // record for contributes nothing rather than a guessed position.
                // ⛔ THE `cm -> address` INDEX IS DELETED (it was 256 entries per block, 88% of the node's
                // footprint). A caller naming its notes by commitment must also name WHERE they are: it
                // already holds `(ident, slot)` sealed in its account-bucket entry and already sends
                // `positions_hex`, so `addrs_hex` simply says which record each cm sits in. Nothing is
                // guessed — an unnamed cm contributes nothing, exactly as an unplaceable one did before.
                let addrs = json_str_field(body, "addrs_hex")
                    .and_then(|h| hex_decode(&h))
                    .unwrap_or_default();
                let mut rebuilt = Vec::with_capacity(cms.len() * 9);
                for (ci, cm) in cms.iter().enumerate() {
                    let named = addrs.get(ci * 8..ci * 8 + 8).map(|b| {
                        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                    });
                    // ⭐ THE COMMITMENT OUTRANKS THE NAMED ADDRESS. A caller's stored position can be wrong
                    // for reasons it cannot see (measured live: OLI served u32-TRUNCATED addresses, so every
                    // restored wallet named garbage and this loop skipped its note). When THIS node's own
                    // cm→address index can place the commitment, use that — identify the note by what it IS.
                    // The named address stays as the fallback for a cm this node has not indexed (e.g. its
                    // target never rode a page it adopted). cons: none — one hash lookup per cm, no state.
                    let named = rt.node().da_seq_at_note_cm(cm).or(named);
                    if let Some(addr) = named {
                        // ⛔ RESOLVE THE SLOT, NEVER ASSUME 0. This pushed a hardcoded 0, so the node served
                        // the copath for the FIRST note in the block instead of the caller's. The path was
                        // well-formed and for the wrong leaf, so it could not reproduce the spend root and
                        // `install_copath` fail-closed on every attempt — measured as "install at absolute
                        // leaf index 7638016: REJECTED" while the note actually sat at slot 187. A wrong slot
                        // is indistinguishable from a corrupt path at the point of failure, which is why it
                        // survived several rounds of looking elsewhere.
                        let want = crate::spend_frontier::note_leaf_of(cm); // §AO: the leaf IS the commitment
                        let slot = rt
                            .node()
                            .da_block_leaves(addr)
                            .and_then(|lv| lv.iter().position(|l| *l == want));
                        // ⛔ A COPATH THIS NODE CANNOT SERVE MUST SAY WHY. A skip here leaves the cm out
                        // of the answer, and the WALLET reads that silence as "witness attempt DECLINED by
                        // the node" — which a recipient's whole balance then hangs on. MEASURED 2026-08-31
                        // (gate run 20, scratch musd-ecocheck-vg2COH): W2 FOUND its 7.0 note (621ms, "1
                        // owned total") and still reported 0.0/present=None, and nothing on either side
                        // said WHICH refusal applied. The two are different bugs: an address we do not
                        // hold is a BACKFILL GAP (the record is real, the bytes are not here yet), while
                        // an address we DO hold whose leaves lack the cm means the caller named the wrong
                        // record. One line separates them.
                        //
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a reason and a record ADDRESS — a dense chain
                        // coordinate this route already accepts as INPUT and already answers over. No cm,
                        // note, amount, key, owner or balance is named.
                        let Some(slot) = slot else {
                            match rt.node().da_block_leaves(addr) {
                                None => eprintln!(
                                    "[copath] cannot serve record {addr}: this node does not hold it yet                                      (backfill gap) — the record is real, the bytes are not here"
                                ),
                                Some(lv) => eprintln!(
                                    "[copath] cannot serve record {addr}: held, but its {} leaf/leaves do                                      not contain the named note — never a guessed slot",
                                    lv.len()
                                ),
                            }
                            continue;
                        };
                        rebuilt.extend_from_slice(&addr.to_le_bytes());
                        rebuilt.push(slot as u8);
                    } else {
                        eprintln!(
                            "[copath] cannot serve: no address for this cm — the caller named none and                              this node has no index entry for it"
                        );
                    }
                }
                if !rebuilt.is_empty() {
                    raw = rebuilt;
                } else {
                    // DB-94: the caller named commitments and NONE resolved to a record that holds it. The
                    // caller's own positions are then the only lead — verify the leaf at each before serving,
                    // never hand back another note's copath (run 96: a stale wallet position served as-is
                    // poisoned a spendable change note for the whole session).
                    let mut verified = Vec::with_capacity(raw.len());
                    let mut off = 0;
                    let mut ci = 0usize;
                    while off + 9 <= raw.len() {
                        let mut sq = [0u8; 8];
                        sq.copy_from_slice(&raw[off..off + 8]);
                        let addr = u64::from_le_bytes(sq);
                        let slot = raw[off + 8] as usize;
                        let ok = cms.get(ci).map_or(false, |cm| {
                            let want = crate::spend_frontier::note_leaf_of(cm);
                            rt.node().da_block_leaves(addr).map_or(false, |lv| lv.get(slot) == Some(&want))
                        });
                        if ok {
                            verified.extend_from_slice(&raw[off..off + 9]);
                        } else {
                            eprintln!(
                                "[copath] the caller's position (record {addr}, slot {slot}) does not hold the \
                                 named note on this node — not served (a stale position, never a guessed copath)"
                            );
                        }
                        off += 9;
                        ci += 1;
                    }
                    raw = verified;
                }
            }
            // ⭐⭐⭐ ONE COORDINATE ON THE WIRE: THE ABSOLUTE LEAF INDEX.
            //
            // user 2026-08-10: *"the copath tree doesnt have to be fixed to 256 anymore since we removed the
            // 256 cover we can build the real architecture"*.
            //
            // This used to answer in the block-as-tree-layer geometry: an in-block subtree path plus an upper
            // path over block roots, addressed by `seq(8) ‖ slot(1)` and reported at `ordinal * 256 + slot`.
            // Both halves are gone with the cover — a block is a BATCH OF APPENDS now, not a tree layer, so
            // there is no in-block subtree to serve and no width to multiply by.
            //
            // The caller names its note's ABSOLUTE LEAF INDEX, which it already holds: `record_note_payload`
            // seals `spend_frontier.count()` into the owner's `AccountEntry` at the moment the note is
            // appended. `indexes_hex` is a batch of u64 LE indexes, cover-padded by the caller to a CONSTANT
            // count exactly as the old position batch was, so which entry is real is not observable here, and
            // the answer is identical for every caller asking about the same index (selector-independent).
            //
            // `positions_hex` / `cms_hex` are still accepted for callers that hold only a record coordinate;
            // they resolve through the record's own leaves, never through a width constant.
            let idxs = json_str_field(body, "indexes_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // ⭐ CARRY `(record_addr, slot)` ALONGSIDE THE LEAF INDEX.
            //
            // This was a bare `Vec<u64>` of absolute leaf indices, which threw away the two coordinates the
            // IN-BLOCK copath is built from. That discard is why restoring the copath looked impossible: by
            // the time the serve loop ran, the only thing left was a leaf number.
            let mut wanted: Vec<(u64, u64, u8)> = idxs
                .chunks_exact(8)
                .map(|c| {
                    // A bare leaf index names no record, so this caller gets the leaf back and no in-block
                    // copath. `positions_hex` / `cms_hex` are the addressed forms and both serve a copath.
                    (
                        u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]),
                        u64::MAX,
                        0u8,
                    )
                })
                .collect();
            if wanted.is_empty() {
                // Legacy `seq ‖ slot`: resolve the record's leaves and take the note's own leaf. The record
                // contributes exactly the leaves it carries, so this is exact whether a block holds one note
                // or fifty — there is no multiplier to get wrong.
                let mut off = 0;
                while off + 9 <= raw.len() {
                    let mut sq = [0u8; 8];
                    sq.copy_from_slice(&raw[off..off + 8]);
                    let seq = u64::from_le_bytes(sq);
                    let slot = raw[off + 8] as usize;
                    off += 9;
                    // ⭐⭐⭐ RESOLVE BY THE NOTE'S OWN COMMITMENT WHEN THE POSITION IS UNKNOWN.
                    //
                    // MEASURED 2026-08-11, live pair at height 12,171:
                    //     [receive-capture] untracked owned note at record 18446744073709551615/slot 0
                    //                       — declined by the node
                    // `18446744073709551615` is `u64::MAX`, the unknown-position sentinel. A wallet that had
                    // decapped and OWNED a note could not say where it sat, so it asked for a witness at a
                    // nonsense address and was refused — the note was never witnessed and every spend called
                    // it untracked. A note you own and cannot spend is FUND LOSS.
                    //
                    // `da_seq_at_note_cm` is the cm -> address index this file has cited for months and did
                    // not have until now. One hash lookup, cost independent of height/blocks/notes/age, so it
                    // answers for a note of ANY age — identify the note by what it IS, never by where some
                    // other node happened to put it.
                    let seq = if seq == u64::MAX {
                        let i = (off - 9) / 9;
                        cms.get(i)
                            .and_then(|c| rt.node().da_seq_at_note_cm(c))
                            .unwrap_or(seq)
                    } else {
                        seq
                    };
                    let addr = if rt.node().da_record_ordinal(seq).is_some() {
                        seq
                    } else {
                        rt.node().da_addr_at_ordinal(seq).unwrap_or(seq)
                    };
                    match rt.node().da_block_leaves(addr) {
                        Some(lv) if slot < lv.len() => {
                            // The record's leaves are a contiguous run in the frontier; the note's index is
                            // that run's start plus its offset. `da_record_leaf_start` is the run's start.
                            match rt.node().da_record_leaf_start(addr) {
                                Some(base) => wanted.push((base + slot as u64, addr, slot as u8)),
                                // ⭐ FETCHED-RECORD FIX (task #21 TRUE ROOT, MEASURED 2026-08-13): a record
                                // this node obtained by FETCHING has its leaves (da_block_leaves ok) but no
                                // FRONTIER leaf-start (da_leafstart_mem is only filled when THIS node folded
                                // the block into its own frontier at that ordinal). The old `None` pushed
                                // copath_addr=MAX, which the serve then skipped entirely — refusing membership
                                // for a note whose record is right here. But the IN-BLOCK copath does NOT need
                                // the global leaf-start: it folds the record's OWN 256 leaves to the block
                                // root (da_note_copath_in_block). leaf-start is only the response's leaf_index
                                // METADATA. So serve the in-block copath with a metadata index of `slot` — the
                                // membership carrier proves `leaf ∈ block_root` correctly regardless. This is
                                // what makes a cross-node send settle for a re-fetched note. cons: the served
                                // leaf_index is record-relative not frontier-absolute when leaf-start is
                                // unknown — harmless, the carrier uses the block_root, not the absolute index.
                                None => wanted.push((slot as u64, addr, slot as u8)),
                            }
                        }
                        _ => wanted.push((u64::MAX, u64::MAX, 0)),
                    }
                }
            }
            let mut arr = String::from("[");
            let mut first = true;
            // ⭐ NO POSITIONS SENT? ANSWER FROM THE COMMITMENTS. The wallet omits a position it does not
            // have (it used to send `u64::MAX`, which the node then tried to resolve as a real address and
            // refused — leaving an owned note permanently unwitnessed). The cm is the coordinate that means
            // the same thing on every node, and `da_seq_at_note_cm` resolves it in one hash lookup whose cost
            // does not depend on height, blocks, notes or how long ago the note arrived.
            if wanted.is_empty() {
                for c in cms.iter() {
                    // ⭐ THREE-WAY NONE PROBE (task #21 true-root measurement): for a cm the wallet owns but
                    // whose membership this node cannot build, name WHICH of the three lookups is None —
                    // seq (cm→addr index+fallback), leaf_start (addr→base), or block_leaves (addr→leaves).
                    // ⛔ DB-350: this line printed a 6-byte PREFIX of the wallet's commitment, the record address and
                    // the leaf index — the note's identity and position, persisted in node.log where a node-first
                    // host's operator reads it. Two booleans and a length keep the probe's whole job.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: no commitment byte, address or index is printed.
                    {
                        let seq = rt.node().da_seq_at_note_cm(c);
                        let ls = seq.and_then(|a| rt.node().da_record_leaf_start(a));
                        let bl = seq
                            .and_then(|a| rt.node().da_block_leaves(a))
                            .map(|l| l.len());
                        eprintln!(
                            "[copath-3way] a cm-named copath read: record placed={} leaf_start known={} \
                             block_leaves_len={:?}",
                            seq.is_some(),
                            ls.is_some(),
                            bl
                        );
                    }
                    match rt.node().da_seq_at_note_cm(c) {
                        Some(a2) => match rt.node().da_record_leaf_start(a2) {
                            Some(base) => {
                                // WHICH slot in that record is this commitment? Answer it here rather than
                                // assuming 0 — a cm-addressed request must be served exactly like a
                                // position-addressed one, or the copath refolds to the wrong leaf.
                                let slot = rt
                                    .node()
                                    .da_block_leaves(a2)
                                    .and_then(|lv| {
                                        let want = crate::spend_frontier::note_leaf_of(c); // §AO: the leaf IS the commitment
                                        lv.iter().position(|l| *l == want)
                                    })
                                    .unwrap_or(0) as u8;
                                wanted.push((base + slot as u64, a2, slot));
                            }
                            None => wanted.push((u64::MAX, u64::MAX, 0)),
                        },
                        None => wanted.push((u64::MAX, u64::MAX, 0)),
                    }
                }
            }
            for (index, copath_addr, copath_slot) in wanted {
                // ⭐⭐⭐ UNKNOWN IS -1 ON THE WIRE, NEVER `u64::MAX`. `index == u64::MAX` is the internal
                // not-found sentinel; serialising it as a NUMBER made the response say
                // `"ordinal":18446744073709551615`, which a wallet parses as a perfectly valid ordinal and
                // turns into a garbage leaf index — silently placing its note in the wrong slot. A negative
                // value cannot be mistaken for a position. (Caught by
                // `note_copath_serves_the_append_ordinal_…`, whose parser overflowed on it — the overflow
                // was the wire wart announcing itself.)
                let ord_disp: i64 = if index == u64::MAX { -1 } else { index as i64 };
                if !first {
                    arr.push(',');
                }
                first = false;
                // RAW LANES per digest — the membership family's one wire form (the carrier that
                // attaches this copath folds the roots `/membership_roots` serves in the same form).
                let hexdigests = |ds: &[crate::spend_frontier::Digest4]| -> String {
                    let mut s = String::with_capacity(ds.len() * 2 * crate::spend_frontier::DIGEST_LANE_BYTES);
                    for d in ds {
                        s.push_str(&hex_encode(&crate::spend_frontier::digest_to_lane_bytes(d)));
                    }
                    s
                };
                // ⛔⛔⛔ THE SERVER-SIDE SPEND COPATH IS DELETED. IT WAS AN MMR-PEAK WINDOW.
                //
                // user 2026-08-11: "if it has to sit in the mmr peak that sounds like a banned window bug" …
                // "so the mmr peak refusal is removed".
                //
                // `da_leaf_copath` refused any COMPLETED sibling span that was not, at that instant, an MMR
                // peak. Which spans are peaks depends on the leaf COUNT, so a note servable at height 3,000
                // became permanently unservable at 144,000 — a refused span is an owned note that can never be
                // spent, decided by chain height. A treeless node has no truthful source for an interior span,
                // so the only honest fix is REMOVAL, never a wider bound.
                //
                // The spender is the only party that can hold this truthfully: it captures its note's authpath
                // ONCE at receipt (its own block fresh, left siblings ARE the peaks) and advances that witness
                // forward. This endpoint now says so explicitly instead of returning an empty array that reads
                // as "the node had nothing" — silence is what let a window masquerade as a missing record.
                // ⭐⭐⭐ THE IN-BLOCK COPATH IS SERVED AGAIN. ONLY THE DEPTH-32 ONE HAD THE WINDOW.
                //
                // Removing the MMR-peak refusal was right — a span that is a peak at height 3,000 and not one
                // at 144,000 refuses an owned note for chain height, which is fund loss. But the removal took
                // BOTH copaths with it, and they are not the same object:
                //
                //   * FULL depth-32 spend-frontier copath — needs interior MMR nodes a treeless node cannot
                //     truthfully produce, and which spans are available depends on the leaf COUNT. That is
                //     the window. It stays removed, and membership no longer asks for it.
                //   * IN-BLOCK copath — the path of one leaf inside its OWN record's leaf set. Its shape is
                //     fixed the moment the block is recorded, every sibling is in that same record, and the
                //     cost has NO term in chain height, block count, note count or age. `da_block_leaves`
                //     regenerates it from the record forever. There is no window here to remove.
                //
                // MEASURED 2026-08-11 on a real Send press at height 56,973, with the exact reason finally
                // surfaced: `/note_copath entry carried no usable block_root_hex`. The note-membership
                // carrier proves `leaf ∈ block_root` and then folds every later block root into the O(1)
                // accumulator — so with this half missing, membership could not be built for ANY note, at any
                // height, on any node. Deleting the window had disabled the thing that replaced it.
                let in_block = if copath_addr == u64::MAX {
                    None
                } else {
                    rt.node().da_note_copath_in_block(copath_addr, copath_slot)
                };
                // ⭐ A COPATH MISS REGISTERS THE WANT — MEASURED 2026-08-13 (send #6 refusal, exact error
                // `no usable block_root_hex`): a note received before a restart could not be SPENT because
                // this node's RAM record store no longer held its record, and this serve refused forever
                // without ever ASKING for the record — the one read that proves the note mattered was the
                // one read that fetched nothing. Registering the want here routes it through the existing
                // refill machinery (by-id/ordinal asks, bulk-first, parity-repair), so the wallet's retry
                // finds the record served. Fail-closed semantics unchanged: THIS response still refuses.
                // cons: one want-set entry per missed copath ask (drains on the fetched record; bounded by
                // the wallet's own owned-note count — never a scan-wide quantity); cons otherwise: none.
                if in_block.is_none() && copath_addr != u64::MAX {
                    // Loud so the cross-node record-replication gap is MEASURABLE, not silent. cons: one line per
                    // missed copath ask (bounded by the wallet's owned-note count).
                    // ⛔ DB-350: it named the exact `(record address, slot)` of the note a wallet was about to spend — a
                    // which-note record in node.log. The by-id want it announces already carries the record's public
                    // address to the peer (census `Ask::record_by_id`); the log keeps the event, not the coordinate.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed sentence — no commitment, address, slot or owner.
                    eprintln!(
                        "[copath-want] a wallet's membership read missed a record this node places but does not \
                         hold — its by-id want is registered; a peer holding it must serve it before the spend can \
                         prove membership."
                    );
                    rt.node_mut().want_record_at_id(copath_addr);
                }
                match in_block {
                    Some((sibs, dirs, root)) => {
                        let dirbits: String =
                            dirs.iter().map(|d| if *d { '1' } else { '0' }).collect();
                        arr.push_str(&format!(
                            "{{\"siblings_hex\":\"{}\",\"dirs\":\"{}\",\"block_root_hex\":\"{}\",\
                             \"ordinal\":{ord_disp},\"leaf_index\":{ord_disp},\"full_siblings_hex\":\"\",\
                             \"full_dirs\":\"\",\"spend_root_hex\":\"\",\
                             \"served\":true,\"depth\":{},\"required_depth\":{},\
                             \"reason\":\"in-block copath (fixed record shape, no height term); the \
                             depth-32 frontier copath stays removed\"}}",
                            hexdigests(&sibs),
                            dirbits,
                            hexdigests(&[root]),
                            sibs.len(),
                            usdm_decider::note_membership_air::IN_BLOCK_DEPTH,
                        ));
                    }
                    None => {
                        arr.push_str(&format!(
                            "{{\"siblings_hex\":\"\",\"dirs\":\"\",\"block_root_hex\":\"\",\
                             \"ordinal\":{ord_disp},\"leaf_index\":{ord_disp},\"full_siblings_hex\":\"\",\
                             \"full_dirs\":\"\",\"spend_root_hex\":\"\",\
                             \"served\":false,\"reason\":\"this node holds no record at that address, so \
                             it can regenerate no leaves for it — ask a node that has the record\"}}"
                        ));
                    }
                }
            }
            arr.push(']');
            (200, format!("{{\"status\":\"OK\",\"copaths\":{}}}", arr))
        }
        ("POST", "/note_ordinal_by_cm") | ("GET", "/note_ordinal_by_cm") => {
            // ⭐⭐⭐ RESOLVE A NOTE TO **THIS NODE'S** DENSE ORDINAL, from its commitment.
            //
            // The account bucket files a block-derived record ADDRESS so the coordinate means the same thing
            // on every node. But the note serve (`pq_notes_from`) pages by DENSE ORDINAL, and the two spaces
            // are different: measured live, a bucket named `seq=33332` while the wallet's chain top was
            // 28950, so `fetch_note_at` asked for a position that does not exist in the served stream and the
            // node answered "0 notes at this record". The payment was recorded, found by the bucket, and
            // still unreachable.
            //
            // A commitment is the one identifier that survives the trip between nodes, so the wallet names
            // the note and each node answers with ITS OWN ordinal — cm -> address (`da_seq_at_note_cm`) ->
            // ordinal (`da_record_ordinal`). Identify the note by what it IS, not by where a peer put it.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: the caller cover-pads its cm batch to a CONSTANT count exactly as
            // it does elsewhere, so which entry is real is unobservable; the answer is identical for every
            // caller asking about the same cm (selector-independent), and it names no amount, key or owner.
            let raw = json_str_field(body, "cms_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let addrs = json_str_field(body, "addrs_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let mut arr = String::from("[");
            let mut slots = String::from("[");
            for (i, c) in raw.chunks_exact(32).enumerate() {
                if i > 0 {
                    arr.push(',');
                }
                let mut cm = [0u8; 32];
                cm.copy_from_slice(c);
                // -1 = this node cannot place the note. Never a guessed position: a wrong ordinal reads
                // someone else's record, which is worse than an honest "I don't have it".
                // -1 = this node cannot place the note. Never a guessed position: a wrong ordinal reads
                // someone else's record, which is worse than an honest "I don't have it".
                //
                // The `cm -> address` index is DELETED, so the caller names the record it already knows (from
                // its account-bucket entry) and this maps record -> dense ordinal — a PER-BLOCK map (24
                // entries at 24 blocks), never a per-note one.
                // ⛔⛔⛔ `let _ = cm;` THREW AWAY THE COMMITMENT, SO THIS ENDPOINT COULD ONLY EVER ANSWER -1.
                //
                // The comment above says the `cm -> address` index is DELETED and the caller must name the
                // record itself. That is STALE: `da_seq_at_note_cm` exists and works — `/note_copath` resolves
                // by commitment with it on every call. Two endpoints answering "where is this note?", one
                // using the live resolver and one asserting it was gone.
                //
                // MEASURED 2026-08-12 on the live pair, one faucet-credited note, same commitment:
                //   /note_copath        by cm -> served=true, block_root_hex 64 chars
                //   /note_ordinal_by_cm by cm -> ordinal=[-1] at t+2s, +10s, +30s, +60s
                // Never populates, because the cm was discarded and `addrs` is empty when a caller sends only
                // `cms_hex` — which is exactly what the wallet's `resolve_position_by_cm` sends. Every send
                // then failed with "the node cannot place this note", about a note the node could place.
                //
                // ONE RESOLVER: use the address the caller named if it gave one, else resolve the commitment
                // the same way `/note_copath` does. Identify the note by what it IS. No new index, no storage
                // — `da_seq_at_note_cm` is the O(1) lookup this file has cited for months and already holds.
                let named = addrs
                    .get(i * 8..i * 8 + 8)
                    .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                    .or_else(|| rt.node().da_seq_at_note_cm(&cm));
                // ⛔⛔⛔ ANSWER THE RECORD ADDRESS, NOT THE DENSE ORDINAL — THE ORDINAL DIES ON RESTART.
                //
                // `da_record_ordinal` reads `da_ord_mem`, whose own doc says it "shares an IN-MEMORY
                // lifetime: a restart empties it". So every note recorded before a node restart answered -1
                // here — a note you own becomes unplaceable, and therefore unspendable, because your node
                // restarted. That is fund loss by age, and the note never changed.
                //
                // MEASURED 2026-08-12 on the live pair, same wallet, same chain:
                //   note dripped AFTER the restart  -> ordinal [2322]   ✅
                //   the wallet's pre-restart notes  -> -1               ❌ every send refused
                // while `/note_copath` served those SAME notes correctly, because `cm -> address` is durable
                // and `address -> dense ordinal` is not.
                //
                // The caller does not want a dense ordinal: `resolve_position_by_cm` hands this value straight
                // back as `by_record_id`, and both that fetch and `/note_copath` resolve a RECORD ADDRESS.
                // Returning the address gives the consumer exactly the coordinate it uses, from the durable
                // index, with no map to rebuild and nothing new stored.
                // ⛔⛔⛔ A MISS MUST ASK A PEER, NOT JUST REFUSE. "THE DA IS THE LEDGER" IS THE WHOLE DESIGN.
                //
                // `da_mem` and `da_targets_mem` are in-memory by DESIGN — only the O(1) frontier snapshot
                // persists (#106), because records are meant to live on the NETWORK and be refetched. But
                // this endpoint answered -1 and stopped, so a node that had restarted told every wallet "I
                // cannot place this note" about notes the chain still holds. An owned note then became
                // unspendable because ONE node forgot it, which is both fund loss and the witness-server
                // dependency the trustless cardinal forbids — the wallet had to reach the one node that
                // happened to still hold its record.
                //
                // MEASURED 2026-08-12, live pair, wallet holding 47,000.00 across 4+ notes, 3 node restarts:
                //   notes credited since boot -> resolve       older notes -> -1, every send refused
                //
                // `want_record_at_id` is the existing backfill ask — the same path a missing sibling record
                // already uses ("the node registered a want for the missing sibling record and asked its
                // peer"). Registering the want here turns a permanent refusal into a fetch: the record
                // arrives from a peer and the next attempt resolves. Still fail-closed for THIS call — it
                // returns -1 rather than guessing a position — so nothing is admitted on a miss.
                //
                // cons: none — `wanted_record_ids` is already bounded to TX_REQ_FIXED_COUNT and drains as
                // wants are asked, so this adds no growth and no new state; a node that genuinely never held
                // the record simply gets nothing back and still answers -1.
                if named.is_none() {
                    if let Some(rid) = addrs.get(i * 8..i * 8 + 8).map(|b| {
                        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                    }) {
                        rt.node_mut().want_record_at_id(rid);
                    }
                }
                let ord: i64 = named.map(|addr| addr as i64).unwrap_or(-1);
                arr.push_str(&format!("{ord}"));
                // ⭐ THE SLOT COMES FROM THE RECORD, NOT FROM WHOEVER WROTE THE BUCKET ENTRY. An account-bucket
                // entry is sealed by the note's WRITER (a payer, or this node crediting), before the record is
                // assembled; the served order of a record is fixed only at assembly (`da_record_notes` lays the
                // real notes into the record's constant cover shape), so the writer cannot know the slot and
                // files 0. The wallet then asked slot 0 for a note the record serves at slot 1 and read "not in
                // what this record served". This door already answers "where is this commitment" by RECORD;
                // answer the SLOT from the same record: one indexed record read, a compare over its constant
                // 256 notes, no new index, nothing stored.
                // ROOT-LAYER: the record's assembled order is PRODUCED here, in the node; the writer's hint can
                // never be right by construction, so the coordinate is answered where it is made.
                // MEASURED: 2026-09-21, live testnet origin 27780 — `POST /note_ordinal_by_cm` for the wallet's
                // 25 USDm note answered ordinal 185067378847309828; the by-id serve of that record lists the
                // note at `slot: 1`; the bucket entry and the store restore both said 0, and the wallet logged
                // "the node served 1 note(s) at this record NON-PENDING and NONE carries our commitment" twice
                // per send after every restart. After: the same call answers `slots: [1]`.
                // MUST-STAY-GREEN: `ordinals` unchanged in name and meaning; a cm this node cannot place answers
                // -1 in both arrays; the by-id serve's own `slot` field is the same numbering.
                let slot: i64 = named
                    .and_then(|addr| rt.node().da_record_notes(addr))
                    .and_then(|blob| blob.chunks_exact(crate::cover::PQ_NOTE_BYTES).position(|n| n[..32] == cm))
                    .map(|p| p as i64)
                    .unwrap_or(-1);
                if i > 0 {
                    slots.push(',');
                }
                slots.push_str(&format!("{slot}"));
            }
            arr.push(']');
            slots.push(']');
            (200, format!("{{\"status\":\"OK\",\"ordinals\":{arr},\"slots\":{slots}}}"))
        }
        ("POST", "/account_bucket") | ("GET", "/account_bucket") => {
            // ⭐ H5 / DB-273 (C): RETIRED. The bucket id is a per-WALLET constant (census `Ask::account_bucket`, LINKAGE); the
            // wallet stopped asking (DB-273 L5) and no block or transaction carries account targets (consensus + pool
            // refuse them), so this route records no want and no node ever sends a bucket ask on a caller's behalf.
            #[allow(clippy::needless_return)]
            if crate::protocol::ACCOUNT_BUCKET_RETIRED {
                return (200, "{\"status\":\"RETIRED\",\"error\":\"the account-bucket lookup is retired (DB-273 C): detection is OLI's\"}".to_string());
            }
            // ACCOUNT-INDEXED RESTORE: one lookup, constant response. The answer is the same width for an
            // account that has never been paid as for one at capacity, so asking reveals nothing — and the
            // entries inside are sealed to the account owner, so serving them reveals nothing either.
            let b = json_str_field(body, "bucket_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            if b.len() != 32 {
                return (200, err_json("BAD_BUCKET"));
            }
            let mut bucket = [0u8; 32];
            bucket.copy_from_slice(&b);
            let blob = {
                let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
                let b = g.node().account_bucket_blob(&bucket);
                // ⭐ NOTHING HERE? GO AND GET IT. A recipient's wallet learns its note's ordinal from this
                // bucket; a node that never recorded the payment answers empty, so the wallet never names an
                // ordinal and the targeted record fetch never fires. That is why settles were intermittent.
                // The request is cover-padded (see `wanted_buckets_padded`) because a bucket id names an
                // account.
                // Emptiness is judged on the REAL entries: `b` is cover-padded to a constant width and is
                // never empty, so testing it would record no want and the node would never ask.
                // ⛔⛔⛔ A BUCKET IS NEVER "COMPLETE" — IT GROWS. This registered a want ONLY when the bucket
                // was entirely empty, so the FIRST answer became the LAST: a node that received one entry
                // never asked again, and every note credited to that account afterwards was invisible to it
                // forever. MEASURED end to end: a node that joined after the payments held 1 of 5 entries and
                // reported `account bucket read OK: 1 owned position(s)` — a confident, wrong answer — while
                // the node that had been present served the same seed 0.55 / 5. The wallet had no way to know
                // it had been told a partial truth, which is the fund-loss shape the cardinals forbid: an
                // owned note that can never be found.
                //
                // Ask on every read. `adopt_account_bucket` appends ONLY entries this node lacks, so
                // re-asking is idempotent; the request is already cover-padded to a constant width
                // (`wanted_buckets_padded`), so asking always costs the same and reveals nothing more than
                // asking once. No window, no cap, no "already fetched" state to go stale.
                g.node_mut().want_account_bucket(bucket);
                b
            };
            // ⛔ SAME DEFECT AS THE NOTES SERVE, SAME COST: an unfetched bucket and a genuinely empty one
            // are DIFFERENT answers, and returning both as plain OK tells a wallet "you own nothing".
            // The account bucket is the ONE lookup a seed-only restore stands on — a recipient whose bucket
            // has not arrived yet reads a 0 balance and has no way to know it should ask again. MEASURED:
            // three sends all returned ok and the recipient reported 0.0 owned 0, poll after poll.
            //
            // `pending` is true exactly when we hold no real entries for this bucket and have therefore
            // registered a want for it, i.e. the answer is incomplete through no fault of the caller. It
            // reports only whether THIS node has fetched it yet — never who asked, never what they own, and
            // it is the same answer for every caller asking about the same bucket.
            // `pending` = a fetch is OUTSTANDING, never merely "no entries". Reporting emptiness as pending
            // made it true forever for every bucket (measured: `pending: true` for an all-zeros probe that
            // can never have entries), so a caller could not tell an in-flight bucket from an empty one.
            let pending = rt
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .node()
                .bucket_fetch_outstanding(&bucket);
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"blob_hex\":\"{}\",\"pending\":{}}}",
                    hex_encode(&blob),
                    pending
                ),
            )
        }
        ("POST", "/peer_record") | ("GET", "/peer_record") => {
            // BOOTSTRAP ENTRY POINT. Peer records propagate by authenticated gossip, but gossip needs a FIRST
            // link: a fresh node with no seed and no inbound peer holds only itself and can never join. Serving
            // our own record lets ANY existing member bootstrap a newcomer, so the mesh grows from any node
            // rather than a fixed seed list — the shape that scales to unbounded nodes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a node's own ONION ADDRESS and its ML-KEM ENCAPSULATION KEY — both
            // already broadcast to the whole mesh by `announce_peer`, and both public by construction. No note,
            // amount, owner or balance is involved; this says nothing about who transacts, only how to reach a
            // relay. PQ throughout: ML-KEM/ML-DSA, no classical key.
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            match rt.own_peer_record() {
                Some(r) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"peer_id\":\"{}\",\"addr\":\"{}\",\"x_pk_hex\":\"{}\",\"ek_hex\":\"{}\",\"seq\":{}}}",
                        r.peer_id, r.addr, hex_encode(&r.x_pk), hex_encode(&r.ek), r.seq
                    ),
                ),
                None => (200, err_json("ONION_NOT_UP_YET")),
            }
        }
        ("POST", "/canon/records") | ("GET", "/canon/records") => {
            // ⭐ A-F114 2c — THE CANONICAL TAG CHAIN'S RECENT RECORDS, for a wallet's absence carrier: each record's chain
            // index, its block's blue score (the coordinate a wallet's scan counts), its end value, its tag lane and its output
            // leaves, oldest first, from `from`, at most 64 a page.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a CONSTANT broadcast — the tag lanes every block already carries on the wire
            // and the chain values every node derives from them, identical for every caller; nothing is keyed by a
            // nullifier, a note or a key, and the reply does not vary with who asks.
            // SCALE: ≤ 64 records × ~16 KB a page; the window itself is canon_chain::CANON_RECENT_RECORDS records.
            let from = json_num_field(body, "from").unwrap_or(0);
            let want = json_num_field(body, "count").unwrap_or(64).clamp(1, 64) as usize;
            let g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let n = g.node();
            let recs = n.canon_recent.range(from, want);
            let oldest = n.canon_recent.oldest().map_or(-1i128, i128::from);
            let next = n.canon_index;
            let genesis = hex_encode(&crate::canon_chain::digest_bytes(&crate::canon_chain::genesis()));
            drop(g);
            let mut items = Vec::with_capacity(recs.len());
            for (i, c, t, l, score) in recs {
                let tags: Vec<u8> = t.iter().flat_map(|x| x.iter().copied()).collect();
                let leaves: Vec<u8> = l.iter().flat_map(|d| crate::canon_chain::digest_bytes(d)).collect();
                items.push(format!(
                    "{{\"i\":{i},\"score\":{score},\"end\":\"{}\",\"tags\":\"{}\",\"leaves\":\"{}\"}}",
                    hex_encode(&crate::canon_chain::digest_bytes(&c)),
                    hex_encode(&tags),
                    hex_encode(&leaves)
                ));
            }
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"genesis\":\"{genesis}\",\"oldest\":{oldest},\"next\":{next},\"records\":[{}]}}",
                    items.join(",")
                ),
            )
        }
        ("POST", "/get_nf_fold_inputs") | ("GET", "/get_nf_fold_inputs") => {
            // ⭐⭐⭐ THE CERTIFIED BASE **AND THE SPAN FROM IT TO THE TIP** — the two things a spender needs
            // to build the absence carrier that is the SOLE spend authority.
            //
            // This once looped `for seq in from..from+want` out of `da_fold_mem`, one entry per block held
            // in RAM forever, and that store was deleted for exactly that growth. It is NOT re-added: the
            // span is read out of the BLOCK WINDOW (`Node::nf_fold_inputs_page`), which the node already
            // holds and already cuts at `Dag::horizon_blue_score`, and `nf_fold_base` now follows that same
            // horizon — so what is returned is precisely the difference between the base and A_tip,
            // bounded by `keep_depth`, a protocol constant.
            //
            // Serving only `base_acc` (what stood here) left a spender able to fold nothing, so every
            // wallet send carried an empty absence field and the door answered `REJECT: … carried NO
            // absence proof`.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: a CONSTANT broadcast — chain-wide accumulator values and the
            // committed contents of blocks every node already replicates, identical for every caller. Not
            // a which-item query: nothing is keyed by nullifier, address, scope or key, and the reply does
            // not vary with who asks or what they hold.
            // ⛔⛔⛔ THIS SERVED `nf_unspent_acc()` — THE LIVE A_TIP — UNDER THE NAME `base_acc`, AND THAT
            // IS THE VALUE AN HONEST SPENDER THEN ROOTS ITS PROOF AT.
            //
            // ROOT-LAYER: the base is produced by `Node::nf_fold_base` — genesis on a node that folded the
            // chain itself, the adopted accumulator on a node that DSYNC-jumped — and it is the field the
            // spend gate compares a carried `base_acc` against, twice: the base-state admit lane
            // (`w.base_acc == self.nf_fold_base.0`) and the recognised-base check. Serving the live tip
            // instead means the spender names a base its own door will refuse, and it is not a value any
            // node can vouch for as a starting point: a carrier rooted at the tip attests an EMPTY span.
            //
            // MEASURED: before → every wallet send shipped `nullifier_absence_hex: ""` and the door
            // answered `[nf-gate] REJECT: N input(s) carried NO absence proof`, 0 wallet spends admissible
            // (ecosystem gate run 8yFZ28: `balance never reached 25.0 spendable`). After → `base_acc` is
            // the field the gate checks, and `base_seq`/`a_tip`/`nf_fold_seq` ride with it so a caller can
            // say WHERE it stands instead of guessing.
            //
            // MUST-STAY-GREEN: the wallet's `fetch_fold_base` reads `base_acc` + `base_seq` and its doc
            // already describes exactly this value; `self_build_publish_absence_witness` and both admit
            // lanes read `nf_fold_base` directly and are untouched.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: three chain-wide accumulator values and two block counts,
            // identical for every caller. No per-block series, so nothing here encodes which item, how
            // many, or when.
            let from = json_num_field(body, "from").unwrap_or(0) as usize;
            // The span is bounded by protocol constants (the window's cut plus the in-flight set), and a
            // caller needs ALL of it to reach A_tip — a page that stops short simply never reproduces the
            // accumulator. The clamp is a wire-size bound on one reply, not a limit on the span.
            let want = json_num_field(body, "count").unwrap_or(4096).clamp(1, 16_384) as usize;
            let g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let (base, base_seq) = g.node().nf_fold_base();
            let a_tip = g.node().nf_unspent_acc();
            let fold_seq = g.node().nf_fold_seq();
            let span_len = g.node().nf_fold_inputs_len();
            // ⭐⭐ DB-252 — an incremental page when the caller names a blue-score cursor it chose from PUBLIC time
            // (the start of the previous quantum, identical for every follower polling in it): only the span
            // blocks scored above it, with files read for those alone. A cursor this node cannot serve from (under
            // the window floor) gets the full span, flagged `"delta":false`, which is the complete answer.
            // ROOT-LAYER: the page is PRODUCED here and in `Node::nf_fold_inputs_above` (the span's own window
            // index); the follower only folds what it is served, so shrinking the page at its producer is what
            // shrinks every pass.
            // MEASURED: before, runSEND246 on real processes, the follower's full-span pages grew 2.57 -> 4.62 ->
            // 6.30 -> 7.34 MB, 30-63 s apart, and the witness reached the gate 63 of the ring's 64 blocks stale.
            // After: measured by chain_action_carriage_tests::db252_* this round.
            // MUST-STAY-GREEN: a caller that sends no cursor gets the byte-identical full page it gets today; the
            // db246_* pins; the wallet's nf_carrier follower.
            // DIGITAL-CASH-PRIVACY-REVIEWED: the cursor is a public-time quantum boundary, not the caller's history;
            // the reply is identical for every caller naming it.
            let delta = json_num_field(body, "above_blue_score").and_then(|b| g.node().nf_fold_inputs_above(b));
            let is_delta = delta.is_some();
            let span = match delta {
                Some(d) => d,
                None => g.node().nf_fold_inputs_page(from, want),
            };
            // The public clock the follower quantizes its cursor on; JSON null before this node has a tip.
            let tip_blue_score = match g.node().selected_tip_blue_score() {
                Some(s) => s.to_string(),
                None => "null".to_string(),
            };
            // ⭐⭐ DB-246 — the TIPS OF THE SPAN, under the SAME lock as `a_tip`: a carrier caught up on this page
            // folded exactly `closure(tips)`, the coordinate any node's spend gate derives its gap from.
            // DIGITAL-CASH-PRIVACY-REVIEWED: block ids the span above already serves; identical for every
            // caller, keyed by nothing a caller holds.
            let span_tips = g.node().nf_fold_span_tips();
            drop(g);
            let limbs = |d: &crate::spend_frontier::Digest4| {
                d.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
            };
            let mut blocks = String::from("[");
            for (i, (id, pre, tags)) in span.iter().enumerate() {
                if i > 0 {
                    blocks.push(',');
                }
                let mut tags_hex = String::with_capacity(tags.len() * 64);
                for t in tags {
                    tags_hex.push_str(&hex_encode(t));
                }
                // ⭐ THE BLOCK ID RIDES EACH ENTRY. A follower cannot key on POSITION — the window shifts
                // as blocks age out and the base absorbs them — so the id is what lets it fold each block
                // exactly once across pages. Already public: it is the block's own identifier.
                blocks += &format!(
                    "{{\"id_hex\":\"{}\",\"block_pre\":[{}],\"tags_hex\":\"{tags_hex}\"}}",
                    id.to_hex(),
                    limbs(pre)
                );
            }
            blocks.push(']');
            let tips_hex = span_tips
                .iter()
                .map(|id| format!("\"{}\"", id.to_hex()))
                .collect::<Vec<_>>()
                .join(",");
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"base_acc\":[{}],\"base_seq\":{base_seq},\"a_tip\":[{}],\"nf_fold_seq\":{fold_seq},\"span_len\":{span_len},\"tips_hex\":[{tips_hex}],\"tip_blue_score\":{tip_blue_score},\"delta\":{is_delta},\"blocks\":{blocks}}}",
                    limbs(&base),
                    limbs(&a_tip)
                ),
            )
        }
        ("POST", "/oli_params") | ("GET", "/oli_params") => {
            // The locator index's epoch parameters — everything a wallet needs to locate its shards and
            // rebuild the same A matrix. Carries no wallet data and is identical for every caller.
            let (idx, blocks) = oli_index_ready(rt);
            let epoch_end = oli_index_frontier(blocks);
            let Some(idx) = idx else {
                return (503, "{\"status\":\"BUILDING\",\"reason\":\"the locator index for this epoch is being built off the lock — ask again\"}".to_string());
            };
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"shard_bits\":{},\"epoch_seed\":\"{}\",\"epoch_blocks\":{},\
                     \"shard_buckets\":{},\"s_rows\":{},\"n_lwe\":{},\"bucket_slots\":{},\"wave_shards\":{}}}",
                    idx.shard_bits,
                    hex_encode(&idx.epoch_seed),
                    epoch_end,
                    crate::oli::SHARD_BUCKETS,
                    crate::oli::S_ROWS,
                    crate::oli::N_LWE,
                    crate::oli::BUCKET_SLOTS,
                    crate::oli::WAVE_SHARDS,
                ),
            )
        }
        ("POST", "/oli_hint") | ("GET", "/oli_hint") => {
            // One shard's per-epoch hint (fixed 512 KB). Shared chain data — the same bytes for every
            // wallet — so it is cacheable and reveals nothing about who asked.
            let sid = json_num_field(body, "shard").unwrap_or(0);
            let Some(idx) = oli_index_ready(rt).0 else {
                return (503, "{\"status\":\"BUILDING\",\"reason\":\"the locator index for this epoch is being built off the lock — ask again\"}".to_string());
            };
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"hint_hex\":\"{}\"}}",
                    hex_encode(&idx.shard_hint(sid))
                ),
            )
        }
        ("POST", "/oli_table") | ("GET", "/oli_table") => {
            // ⭐ DB-228 — ONE SHARD'S WHOLE TABLE (the fixed 256 KB `SHARD_BUCKETS × BUCKET_BYTES`): the trivial
            // PIR. The asker receives every bucket, so this node learns only WHICH SHARD was fetched — exactly
            // what an `/oli_hint` request for that shard already told it — and nothing about which bucket (or
            // whose note) was wanted; the hiding is information-theoretic, not computational.
            //
            // WHY A WALLET NEEDS THE WHOLE TABLE (the DB-228 finding): a restoring wallet hides its real note
            // positions among cover in its `/get_my_pq_notes` batch, and this node can separate any cover that
            // is not itself a REAL TAGGED NOTE — it stores every record's reals and regenerates the fill, so it
            // knows which slots are real and which records are idle. The only universe cover can be drawn from
            // is therefore the real entries of the index, in the shards the wallet already fetched.
            //
            // DIGITAL-CASH-PRIVACY-REVIEWED: shard contents are chain-derived, identical for every caller, and
            // were already readable bucket by bucket through `/oli_answer` with un-noised queries; the request
            // names a shard id only. An out-of-range shard answers the same-size all-zero table, so the reply
            // size never says whether a shard holds anything.
            // ROOT-LAYER: served from the SAME epoch-cached `Index` that `/oli_params`, `/oli_hint` and
            // `/oli_answer` answer from — `Index::shard_table` is the one producer of these bytes, and
            // `shard_bits` rides the reply so the asker can tell an epoch change between its params and this
            // table from a miss. The runtime lock is held only to clone the index handle; the render runs
            // after the guard drops (poison is recovered exactly as every sibling route recovers it).
            // MEASURED: live :27780 (2026-09-26 01:5x, shard_bits 0) — `/oli_hint {"shard":0}` answered
            // 1,048,605 B (the 512 KB hint as hex) in 9-50 ms over 3 asks; this route answers the 262,144 B
            // table as 524,288 hex chars plus its envelope — half the bytes, and no per-ask hint work.
            // MUST-STAY-GREEN: `a_late_clue_is_findable_through_the_real_oli_pir_routes_on_a_verifying_peer`
            // (the PIR routes are untouched) and
            // `db228_the_whole_shard_table_served_by_oli_table_locates_a_note_and_reproduces_the_served_seed`.
            // A request that names no shard is REFUSED, never read as shard 0.
            let Some(sid) = json_num_field(body, "shard") else {
                return (400, err_json("OLI_TABLE_NAMES_NO_SHARD"));
            };
            let Some(idx) = oli_index_ready(rt).0 else {
                return (503, "{\"status\":\"BUILDING\",\"reason\":\"the locator index for this epoch is being built off the lock — ask again\"}".to_string());
            }; // ← `oli_index_ready` holds the rt guard only to read the handle
            let table = idx.shard_table(sid);
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"shard\":{sid},\"shard_bits\":{},\"table_hex\":\"{}\"}}",
                    idx.shard_bits,
                    hex_encode(&table)
                ),
            )
        }
        ("POST", "/oli_answer") => {
            // Answer a batch of PIR queries against ONE shard, in a single pass over that shard's 256 KB
            // table. The queries are LWE-hiding: this node cannot tell which bucket — or whose note — is
            // being looked up, and a garbled answer can only cause the wallet a miss.
            let sid = json_num_field(body, "shard").unwrap_or(0);
            let joined = json_str_field(body, "queries_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let Some(idx) = oli_index_ready(rt).0 else {
                return (503, "{\"status\":\"BUILDING\",\"reason\":\"the locator index for this epoch is being built off the lock — ask again\"}".to_string());
            };
            let qlen = (crate::oli::SHARD_BUCKETS as usize) / crate::oli::BUCKETS_PER_COL * 4;
            if joined.is_empty() || qlen == 0 || joined.len() % qlen != 0 {
                (
                    400,
                    "{\"status\":\"ERR\",\"reason\":\"malformed queries_hex\"}".to_string(),
                )
            } else {
                let queries: Vec<Vec<u8>> = joined.chunks(qlen).map(|c| c.to_vec()).collect();
                match idx.answer(sid, &queries) {
                    Some(answers) => {
                        let mut joined_out =
                            String::with_capacity(answers.len() * crate::oli::S_ROWS * 8);
                        for a in &answers {
                            joined_out.push_str(&hex_encode(a));
                        }
                        (
                            200,
                            format!("{{\"status\":\"OK\",\"answers_hex\":\"{}\"}}", joined_out),
                        )
                    }
                    None => (
                        400,
                        "{\"status\":\"ERR\",\"reason\":\"query shape rejected\"}".to_string(),
                    ),
                }
            }
        }
        ("POST", "/authorize_mint") => {
            // PSM confidential MINT-AUTHORIZATION (Buy-USDm): run the sound gate LIVE — a ≥2/3 bonded-validator
            // threshold attestation over the mint message PLUS the confidential 150% solvency proof
            // (reserve_commit ≥ ratio·liability_commit; NO amounts). Fail-closed: the ZK solvency seam here is
            // `RefuseAllSolvency` (rejects until a real verifier is installed), so a mint is authorized ONLY
            // when the real ZK seam AND a real bonded quorum attesting a real reserve deposit are present.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let (deposit_id, recipient_cm, reserve_commit, liability_commit) = match (
                h32("deposit_id"),
                h32("recipient_cm"),
                h32("reserve_commit"),
                h32("liability_commit"),
            ) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => return (200, err_json("BAD_COMMITMENTS")),
            };
            let ratio_bps = json_num_field(body, "ratio_bps").unwrap_or(0) as u32;
            let proof = json_str_field(body, "solvency_proof")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // Attestors as a flat record concat: `pubkey_len(u16 LE) ‖ pubkey ‖ sig_len(u16 LE) ‖ sig` (hex).
            let ab = json_str_field(body, "attestors_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let mut attestors: Vec<crate::psm::MintAttestor> = Vec::new();
            let mut off = 0;
            while off + 2 <= ab.len() {
                let plen = u16::from_le_bytes([ab[off], ab[off + 1]]) as usize;
                off += 2;
                if off + plen + 2 > ab.len() {
                    break;
                }
                let pubkey = ab[off..off + plen].to_vec();
                off += plen;
                let slen = u16::from_le_bytes([ab[off], ab[off + 1]]) as usize;
                off += 2;
                if off + slen > ab.len() {
                    break;
                }
                let sig = ab[off..off + slen].to_vec();
                off += slen;
                attestors.push(crate::psm::MintAttestor { pubkey, sig });
            }
            let req = crate::psm::MintRequest {
                deposit_id,
                recipient_note_cm: recipient_cm,
                solvency: crate::solvency::SolvencyProof {
                    reserve_commit,
                    liability_commit,
                    ratio_bps,
                    proof,
                },
                attestors,
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let outcome = rt
                .node()
                .authorize_mint(&crate::solvency::RefuseAllSolvency, &req);
            let s = match outcome {
                crate::psm::MintOutcome::Authorized => "AUTHORIZED",
                crate::psm::MintOutcome::InsufficientQuorum => "INSUFFICIENT_QUORUM",
                crate::psm::MintOutcome::Undercollateralized => "UNDERCOLLATERALIZED",
                crate::psm::MintOutcome::Unauthenticated => "UNAUTHENTICATED",
            };
            (200, format!("{{\"status\":\"OK\",\"outcome\":\"{s}\"}}"))
        }
        // ⭐ §BR-2 — THE WALLET'S CO-SIGNED DEPOSIT, over its OWN node. §9.6 for these three doors: (1) no PoW — none of them
        // admits anything into the chain; (2) no object is admitted, so no proof is owed: the leaf is a re-derivation from
        // public chain state checked against the address the caller names, the coins and funding scripts are this node's
        // own watcher cache, and a broadcast hands Bitcoin a transaction Bitcoin itself judges; (3) none can create or move
        // MonerousD value; (4) no replay surface — reads, and a Bitcoin broadcast Bitcoin dedupes by txid; (5) bounded: one
        // cache read, one re-derivation over the live set and the recent ring, one raw transaction ≤ 100 kB; (6) parity
        // with `/btc_deposit_status`, the read these sit beside: the same local-origin admission and the same watch
        // registration (a deposit address this node issued is watched from the moment the wallet names it).
        ("POST", "/btc_deposit_leaf") => {
            let address = json_str_field(body, "address").unwrap_or_default();
            let d_blind = json_str_field(body, "d_blind_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b));
            let depositor = json_str_field(body, "depositor_x_hex").and_then(|h| hex_decode(&h)).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            let (Some(d_blind), Some(depositor)) = (d_blind, depositor) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let leaf = rt.lock().unwrap_or_else(|e| e.into_inner()).node().deposit_leaf_for(&address, &d_blind, &depositor);
            match leaf {
                Some(l) => (
                    200,
                    serde_json::json!({
                        "status": "OK",
                        "k": l.k,
                        "slot_keys_hex": l.slot_keys.iter().map(|k| hex_encode(k)).collect::<Vec<_>>(),
                    })
                    .to_string(),
                ),
                None => (200, err_json("NOT_OUR_DEPOSIT")),
            }
        }
        ("POST", "/btc_deposit_coin") => {
            let address = json_str_field(body, "address").unwrap_or_default();
            let _ = crate::btc_watch::watch_issued_reserve(&address);
            let coins: Vec<serde_json::Value> = crate::btc_watch::coins_cached(&address)
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "txid": crate::btc_tx::txid_display_hex(&c.txid),
                        "vout": c.vout,
                        "value_sats": c.value_sats,
                        "confirmations": c.confirmations,
                        "funding_scripts_hex": crate::btc_watch::funding_scripts_cached(&c.txid)
                            .map(|v| v.iter().map(|x| hex_encode(x)).collect::<Vec<_>>()),
                    })
                })
                .collect();
            (200, serde_json::json!({ "status": "OK", "coins": coins }).to_string())
        }
        ("POST", "/btc_broadcast") => {
            let raw = json_str_field(body, "raw_hex").unwrap_or_default();
            if raw.is_empty() || raw.len() > 200_000 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
                return (200, err_json("BAD_FIELDS"));
            }
            match crate::btc_watch::btc_source(crate::bridge::btc_net()).and_then(|src| src.broadcast(&raw)) {
                Some(txid) => (200, serde_json::json!({ "status": "OK", "txid": txid }).to_string()),
                None => (200, err_json("NOT_ACCEPTED")),
            }
        }
        ("POST", "/btc_deposit_status") | ("GET", "/btc_deposit_status") => {
            // Live READ of the reserve address's CONFIRMED Bitcoin balance (crate::btc_watch → Esplora). The
            // wallet polls this so the Buy tracker shows "waiting for deposit" until the real deposit confirms,
            // then auto-mints. Read-only public chain data; returns confirmed_sats + whether it meets min_sats.
            // Accept EITHER field name — this endpoint historically read `address`, but its sibling
            // `/attest_peg_in` reads `reserve_address`; accepting both keeps every caller working and removes a
            // silent-empty-address footgun (an unrecognized field → empty address → scans nothing → reachable:false).
            let address = json_str_field(body, "address")
                .filter(|s| !s.is_empty())
                .or_else(|| json_str_field(body, "reserve_address"))
                .unwrap_or_default();
            let min_sats = json_num_field(body, "min_sats").unwrap_or(0) as u64;
            // ONE Esplora read → (confirmed, pending). CONFIRMED (mined) is the mint gate; PENDING (in the
            // mempool, not yet mined) is surfaced so the wallet's Buy tracker flips to a LIVE "pending" state
            // the instant the deposit broadcasts, then to "confirmed" when it's mined — a true live mirror.
            // Reads the SELF-MAINTAINING cache (O(1) INSTANT) — a background watcher keeps every reserve address
            // warm over the onion pool, so this RPC never blocks on the slow hidden-service round-trip (which used
            // to time out the wallet's mint poll). Registers the address so it stays watched from here on.
            // DB-121x: a Monero (integrated) address reads this node's own custody-wallet cache instead — a node
            // that holds no custody wallet has never read it and answers 0 (the custodians confirm the mint from
            // their wallets; the wallet's poll here is informational on such a node).
            let (confirmed_sats, pending_sats) = if crate::bridge::is_monero_address(&address) {
                match crate::xmr_watch::confirmed_pending_cached(&address) {
                    Some(v) => v,
                    None => (0, 0),
                }
            } else {
                crate::btc_watch::confirmed_pending_cached(&address)
            };
            let confirmed = min_sats > 0 && confirmed_sats >= min_sats;
            // Echo the address with JSON-punctuation stripped (a bech32 address is alphanumeric + length-bounded
            // by its own format, so this is sanitization, not a cap on a completeness-critical set).
            let safe_addr: String = address
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            (200, format!(
                "{{\"status\":\"OK\",\"address\":\"{}\",\"confirmed_sats\":{},\"pending_sats\":{},\"reachable\":{},\"min_sats\":{},\"confirmed\":{}}}",
                safe_addr, confirmed_sats, pending_sats, !address.is_empty(), min_sats, confirmed
            ))
        }
        ("POST", "/peg_in_confidential") => {
            // #75 — CONFIDENTIAL PEG-IN: NO cleartext amount. The custodian threshold submits the WHIR-bound
            // peg-in carrier + the NEW committed reserve/minted state; the node verifies the ≥2/3 threshold + the
            // carrier against its persisted commitments, advances the opaque digest pair, and records the buyer's
            // confidential note. An observer sees only a commitment swap + a confidential note — no deposit/mint value.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            // A solvency commitment is a compression output the custodian's prover produced, carried in
            // its canonical 32-byte form (`leaf_to_cm_bytes`) and recovered by the injective decode.
            // ⛔ §AG CLASS 9, the silent half: this read FOUR raw LE limbs of an EIGHT-lane digest and
            // left lanes 4..7 zero, so the committed reserve/minted digests the node verified the carrier
            // against were half-width — a different value from the one the custodian proved, and one
            // whose collision resistance was the 62-bit figure §AG widened the digest to escape. A field
            // that is not a canonical digest decodes `None` (BAD_FIELDS), never a truncated commitment.
            let commit = |k: &str| -> Option<crate::spend_frontier::Digest4> {
                let b = json_str_field(body, k).and_then(|h| hex_decode(&h))?;
                let arr = <[u8; 32]>::try_from(b.as_slice()).ok()?;
                crate::spend_frontier::cm_bytes_to_root(&arr)
            };
            let (deposit_id, recipient) = match (h32("deposit_id"), h32("recipient")) {
                (Some(a), Some(b)) => (a, b),
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let (new_rc, new_mc) = match (commit("new_reserve_commit"), commit("new_minted_commit"))
            {
                (Some(a), Some(b)) => (a, b),
                _ => return (200, err_json("BAD_COMMITMENTS")),
            };
            let carrier = json_str_field(body, "carrier_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let note_payload = json_str_field(body, "note_payload")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // ⛔ THE AUTHORIZED AMOUNT + ITS cm BIND. The credit gate refuses unless this carrier proves
            // `note_payload`'s commitment opens to exactly `mint` — otherwise the caller chooses what it
            // receives while the committed pair advances by the authorized figure (minting from nothing).
            // DB-80: the object carries the COMMITTED mint delta, never the amount
            let Some(delta_commit) = commit("delta_commit") else {
                return (200, err_json("BAD_COMMITMENTS"));
            };
            // FUNDS-LOSS-IMPOSSIBLE bond backstop: the WHIR proof that bonded weight ≥ 2× the new reserve. The mint
            // is rejected (Underbonded) without it, so the reserve is always ≤ half the forfeitable bond.
            let bond_backstop = json_str_field(body, "bond_backstop_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let attestors = parse_peg_attestors(
                &json_str_field(body, "attestors_hex")
                    .and_then(|h| hex_decode(&h))
                    .unwrap_or_default(),
            );
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐ DB-273 §19 L1: the credited note's OLI clue, so a seed-only restore finds it on any node. The node
            // refuses a clue the attested `recipient` does not commit to (`peg::peg_in_recipient`), and none at all.
            let Some(owner_clue) = owner_clue_field(body) else {
                return (200, err_json("BAD_OWNER_CLUE"));
            };
            // The mint-amount bind (connect-9f's USDm gate). Restored here after I removed it by
            // mistake while wiring the wrapped twin — the two routes each need their own parse.
            let mint_carrier = json_str_field(body, "mint_carrier_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // The proposal instance the supplied attestations signed over (`peg_in_confidential_msg` v2);
            // absent ⇒ the zero nonce, which those attestations must then have been made over.
            let proposal_nonce = h32("proposal_nonce").unwrap_or([0u8; 32]);
            let outcome = rt.node_mut().peg_in_confidential(
                deposit_id,
                &carrier,
                new_rc,
                new_mc,
                recipient,
                &note_payload,
                delta_commit,
                &mint_carrier,
                &bond_backstop,
                &crate::pqauth::MlDsaVerifier,
                &attestors,
                &owner_clue,
                proposal_nonce,
                None,
            );
            let h = rt.node().tip_height();
            // NOTE: NO `minted` field — the confidential path discloses no amount (that is the whole point).
            // `authorized` = the transition verified here and was PUBLISHED; it applies when a block carries
            // it (`CONFIDENTIAL_PUBLISHED`), on this node exactly as on every peer.
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"authorized\":{},\"mint_height\":{},\"outcome\":\"{}\"}}",
                    matches!(outcome, crate::peg::PegOutcome::ConfidentialPublished),
                    h,
                    peg_outcome_str(&outcome)
                ),
            )
        }
        // (`/peg_out_confidential` stood here — a custodian-supplied-carrier redeem that named only a
        // nullifier and could carry no deletion transition for the note it claimed to burn. Under chain
        // semantics (§CZ) such an object can never be admitted — a burn is a spend, and a spend of a note
        // this chain never held authorises nothing — so the route was a door onto a wall and is gone.
        // The redeem route is `/peg_out_execute`: a welded burn carrier, the note's membership cross-bind
        // and its deletion transition, published as ONE `Class::PegOut` the block applies everywhere.)
        ("POST", "/stake") => {
            // ⭐⭐⭐ DB-237 — STAKE, CLAIM AND UNSTAKE: ONE DOOR, ONE OBJECT. The wallet proves the stake carrier over its own
            // note (`whir_rec_block::prove_stake_carrier_bytes`) and the membership carrier over that note's record, and
            // names the reward and its blind (they open the carrier's `reward_commit`; this node, a bonded custodian, needs
            // them to prove the supply step and seal the leg). Every field is REQUIRED: a missing or non-canonical one is
            // BAD_FIELDS here, never a defaulted value a verifier could be handed.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let dg = |k: &str| h32(k).and_then(|b| crate::spend_frontier::cm_bytes_to_root(&b));
            let bytes = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h));
            let (
                Some(nullifier),
                Some(e_now),
                Some(rate),
                Some(out0_cm),
                Some(out1_cm),
                Some(leaf_commit),
                Some(reward_commit),
                Some(reward),
                Some(reward_blind),
                Some(stake_carrier),
                Some(out0),
                Some(out1),
                Some(mem_carrier),
                Some(mem_tip),
            ) = (
                h32("nullifier"),
                json_num_field(body, "e_now"),
                json_num_field(body, "rate_bps").and_then(|r| u32::try_from(r).ok()),
                dg("out0_cm"),
                dg("out1_cm"),
                dg("leaf_commit"),
                dg("reward_commit"),
                json_num_field(body, "reward"),
                dg("reward_blind"),
                bytes("stake_carrier_hex"),
                bytes("out0_note_hex"),
                bytes("out1_note_hex"),
                bytes("membership_carrier_hex"),
                bytes("membership_tip_hex"),
            )
            else {
                return (200, err_json("BAD_FIELDS"));
            };
            // ⭐ DB-273 §19.3 L2: the two credited notes' OLI clues, read by THE one clue-list codec and keyed to exactly
            // (out0, out1) by their commitments. A missing, extra or foreign record is BAD_FIELDS — never a stand-in owner.
            let Some(clues) = clues_keyed_to_notes(body, &[out0.as_slice(), out1.as_slice()]) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let stmt = crate::stake_tx::StakeHeader {
                nullifier,
                e_now,
                rate_bps: rate,
                out0_cm,
                out1_cm,
                leaf_commit,
                reward_commit,
                new_paid_commit: usdm_decider::poseidon2_compress::zero_digest(), // filled by the supply step
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐ §BR-3 17.6 — ON ANY NODE: a node that holds no stakers' pool opening (every wallet's own node that is not a
            // bonded custodian) relays the stake through the custodial request lane — the reward and its blind sealed per
            // custodian, the rest public — and the lowest-id custodian executes it. A custodian executes it here, inline.
            if !rt.node().holds_stakers_pool_opening() {
                let Some((recipient, note_payload)) = crate::stake_tx::request_public(&stmt, &out0, &out1, &clues) else {
                    return (200, err_json("BAD_FIELDS"));
                };
                let secret = crate::peg_attest::RequestSecret {
                    value_a: u128::from(reward),
                    value_b: u128::from(reward),
                    address: String::new(),
                    owner_clue: clues[1].clone(),
                    d_blind: reward_blind,
                    pay_after: 0,
                    sweep: None,
                };
                let mut sealed = Vec::new();
                for (id, ek) in rt.node().validators().bonded_custodian_eks() {
                    if let Some(blob) = crate::peg_attest::seal_request_to(&ek, &secret) {
                        sealed.push((id, blob));
                    }
                }
                if sealed.is_empty() {
                    return (200, "{\"status\":\"OK\",\"published\":false,\"outcome\":\"NO_CUSTODIANS\"}".to_string());
                }
                let mut req = crate::peg_attest::PegRequest {
                    kind: crate::peg_attest::PEG_REQUEST_STAKE,
                    asset_id: crate::peg::NATIVE_PEG_ASSET_ID,
                    id: nullifier,
                    recipient,
                    note_payload,
                    carrier: stake_carrier,
                    out0_cm,
                    out1_cm,
                    delta_commit: reward_commit,
                    membership_carrier: mem_carrier,
                    membership_tip: mem_tip,
                    leaf_commit,
                    sealed,
                    stamp: 0,
                    ticket: Vec::new(),
                    epoch_ct: Vec::new(),
                    unit: None,
                };
                req.stamp_to(rt.node().required_stamp_bits());
                if let Err(why) = rt.node().peg_request_verify_public(&req) {
                    return (200, format!("{{\"status\":\"OK\",\"published\":false,\"outcome\":\"BAD_REQUEST:{why}\"}}"));
                }
                let now = rt.now_unix_ms();
                if rt.publish_peg_request(&req, now).is_none() {
                    return (200, "{\"status\":\"OK\",\"published\":false,\"outcome\":\"BAD_REQUEST:NOT_ONE_ENCODING\"}".to_string());
                }
                // A-F78: the re-gossip tick seals it again to a custodian that joins before it settles
                rt.node_mut().peg_request_own_secret(&req.slot_key(), secret);
                return (200, "{\"status\":\"OK\",\"published\":true,\"outcome\":\"REQUESTED\"}".to_string());
            }
            let outcome = rt.node_mut().execute_stake(
                stmt,
                &stake_carrier,
                reward,
                reward_blind,
                &mem_carrier,
                &mem_tip,
                &out0,
                &out1,
                &clues,
            );
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"published\":{},\"outcome\":\"{}\"}}",
                    matches!(outcome, crate::peg::PegOutcome::ConfidentialMinted),
                    peg_outcome_str(&outcome)
                ),
            )
        }
        ("POST", "/peg_in_execute") => {
            // ⭐ DB-77 (2026-09-19) — THE DOOR IS A REQUEST, ON ANY NODE. Until today this door executed
            // the mint INLINE and answered NOT_A_CUSTODIAN on every node without a bridge signer, so a
            // wallet whose node held no seat could not mint. Now the door verifies what needs no
            // custodial secret, seals the amounts / reserve address / owner keys per bonded custodian,
            // records the request and gossips it; the custodians propose, attest and publish over the
            // attestation lane; the block credits the note on every node. A poll answers CHAIN STATE
            // first (minted / published), then the request's status. BORROWED-FROM: tBTC v2
            // `revealDeposit`, THORChain observe→sign→publish.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let deposit_id = match h32("deposit_id") {
                Some(a) => a,
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let deposit_value = json_num_field(body, "deposit_value").unwrap_or(0) as u128;
            let mint = json_num_field(body, "mint").unwrap_or(0) as u128;
            let note_payload = json_str_field(body, "note_payload")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let mint_carrier = json_str_field(body, "mint_carrier_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let reserve_address = json_str_field(body, "reserve_address").unwrap_or_default();
            // ⭐ DB-273 §19 L1: the credited note's OLI clue — the ONLY owner this door reads.
            let owner_clue = owner_clue_field(body);
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let mint_height = rt.node().tip_height();
            if rt.node().peg().deposit_minted(&deposit_id) {
                let mint_height = rt.node().peg_minted_height(&deposit_id);
                let credited = note_payload
                    .get(..32)
                    .and_then(|f| <[u8; 32]>::try_from(f).ok())
                    .map(|cm| !rt.node().records_containing_cm(&cm).is_empty())
                    .unwrap_or(false);
                return (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"minted\":true,\"credited\":{credited},\"mint_height\":{mint_height},\"outcome\":\"ALREADY_MINTED\"}}"
                    ),
                );
            }
            if rt.node().peg_in_is_published(&deposit_id)
                && rt.node_mut().peg_in_published_still_pooled(&deposit_id)
            {
                return (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"minted\":false,\"published\":true,\"mint_height\":{mint_height},\"outcome\":\"CONFIDENTIAL_PUBLISHED\"}}"
                    ),
                );
            }
            let gathered = rt.node().peg_attestations_for(&deposit_id).len();
            if let Some(slot) = rt.node().peg_request_slot(&deposit_id) {
                // A slot recorded while this node had no seat holds no payload (nothing to act on). If it
                // is a custodian NOW (bonded since, or the wallet's own node polling), fall through and
                // note the request with the payload so the lane can act; otherwise the poll answers
                // GATHERING (run 97 prep, 2026-09-19: the DB-93 id made the poll and the request one slot).
                let can_act_now = rt.bridge_signer().is_some() && slot.request.is_none();
                if !slot.done && !can_act_now {
                    return (
                        200,
                        format!(
                            "{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"GATHERING\",\"gathering\":true,\"attestations_gathered\":{gathered}}}"
                        ),
                    );
                }
            }
            let Some(owner_clue) = owner_clue else {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:OWNER\"}}"));
            };
            // ⭐ DB-273 §17 condition 4: the recipient the quorum signs is COMPUTED here as a commitment to the clue,
            // never taken from the caller — so the owner is under the signatures before anything mints.
            let recipient = crate::peg::peg_in_recipient(&deposit_id, &owner_clue);
            let Some(cm_limbs) = crate::spend_frontier::note_cm_of(&note_payload) else {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:NOTE\"}}"));
            };
            let Ok(mint_u64) = u64::try_from(mint) else {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:AMOUNT\"}}"));
            };
            if mint == 0 || deposit_value == 0 || reserve_address.is_empty() {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:FIELDS\"}}"));
            }
            // ⭐ §BR-4 B4-2: a debt unit's half (optional) — the unit binds the deposit: its base id is the reserve address's
            // and the request's id is the unit's (`unit_open_tx::unit_deposit_id`). Refused here, before sealing, when the
            // half does not prove or does not bind.
            let unit = match json_str_field(body, "unit_part_hex").and_then(|h| hex_decode(&h)) {
                None => None,
                Some(b) => match crate::chain_object::decode_exact::<crate::unit_open_tx::UnitPart>(&b) {
                    Some(u)
                        if u.verifies()
                            && u.claim.base_deposit_id == crate::peg::deposit_id_for_reserve_address(&reserve_address)
                            && u.claim.deposit_id() == deposit_id =>
                    {
                        Some(u)
                    }
                    _ => return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:UNIT_DOES_NOT_BIND\"}}")),
                },
            };
            // DB-93: the deposit id is the function of the per-swap reserve address (one mint per deposit); the
            // door refuses any other id here, before sealing, so an honest wallet learns it at once.
            if unit.is_none() && deposit_id != crate::peg::deposit_id_for_reserve_address(&reserve_address) {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:DEPOSIT_ID_NOT_FROM_RESERVE_ADDRESS\"}}"));
            }
            // DB-80: the requester commits its mint delta (`delta_commit` = solvency_commit_256(mint, d_blind))
            // and seals the blind to the custodians; the door checks the commitment opens THIS request's
            // amount and that the note opens to it under the carried proof. The amount never rides the wire.
            let _ = mint_u64;
            let delta_commit = match json_str_field(body, "delta_commit").and_then(|h| hex_decode(&h)) {
                Some(b) => match <[u8; 32]>::try_from(b.as_slice()).ok().and_then(|a| crate::spend_frontier::cm_bytes_to_root(&a)) {
                    Some(d) => d,
                    None => return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:DELTA_COMMIT\"}}")),
                },
                None => return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:DELTA_COMMIT\"}}")),
            };
            let d_blind = match json_str_field(body, "d_blind_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b)) {
                Some(d) => d,
                None => return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:D_BLIND\"}}")),
            };
            if delta_commit != crate::peg::PegLedger::mint_delta_commit(mint, d_blind) {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:DELTA_COMMIT_OPENING\"}}"));
            }
            // DB-123: the deposit address must be the reserve's OWN for this blind (the k-of-n custody leaf
            // over the chain's bonded set, tweaked by the blind). A wallet that deposited anywhere else learns
            // it here at once, instead of from a quorum that never gathers; every custodian re-checks it.
            // §BR-2: the co-signed deposit's sweep authorization — required for a Bitcoin deposit (its address binds D)
            let sweep = match sweep_auth_from_json(body) {
                Ok(a) => a,
                Err(why) => return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:{why}\"}}")),
            };
            // SAFE AT SCALE: the address is under ONE vault's keys (`vault_of_reserve_address`; vault 0 — the whole bonded set —
            // on a one-vault chain), and the request is sealed to that vault's custodians below.
            let Some(deposit_vault) = rt.node().vault_of_reserve_address(&reserve_address, &d_blind, sweep.as_ref().map(|a| &a.depositor_x)) else {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:RESERVE_ADDRESS_NOT_OURS\"}}"));
            };
            if !usdm_decider::whir_rec_block::verify_mint_validity_committed_bytes(&mint_carrier, cm_limbs, delta_commit) {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:MINT_CARRIER\"}}"));
            }
            let secret = crate::peg_attest::RequestSecret {
                value_a: deposit_value,
                value_b: mint,
                address: reserve_address.clone(),
                owner_clue,
                d_blind,
                pay_after: 0,
                sweep,
            };
            let mut sealed = Vec::new();
            for (id, ek) in rt.node().custodian_eks_of_vault(deposit_vault) {
                if let Some(blob) = crate::peg_attest::seal_request_to(&ek, &secret) {
                    sealed.push((id, blob));
                }
            }
            if sealed.is_empty() {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"NO_CUSTODIANS\"}}"));
            }
            let mut req = crate::peg_attest::PegRequest {
                kind: crate::peg_attest::PEG_REQUEST_IN,
                // ⛔ the unit class: a Monero deposit mints on Monero's own ledger, a Bitcoin one on the native — the ledger is the
                // deposit address's chain, read by each custodian from its SEALED leg (§19.5b: asset 0 in public for both)
                asset_id: crate::peg::NATIVE_PEG_ASSET_ID,
                id: deposit_id,
                recipient,
                note_payload,
                carrier: mint_carrier,
                out0_cm: usdm_decider::poseidon2_compress::zero_digest(),
                out1_cm: usdm_decider::poseidon2_compress::zero_digest(),
                delta_commit,
                membership_carrier: Vec::new(),
                membership_tip: Vec::new(),
                leaf_commit: usdm_decider::poseidon2_compress::zero_digest(),
                sealed,
                stamp: 0,
                ticket: Vec::new(),
                epoch_ct: Vec::new(),
                unit,
            };
            req.stamp_to(rt.node().required_stamp_bits());
            if let Err(why) = rt.node().peg_request_verify_public(&req) {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:{why}\"}}"));
            }
            let now = rt.now_unix_ms(); // DB-416: the runtime's one clock
            let is_custodian = rt.bridge_signer().is_some();
            // DB-402 R4: note what every peer decodes from the published bytes (one encoding)
            let Some(req) = rt.publish_peg_request(&req, now) else {
                return (200, format!("{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"BAD_REQUEST:PEG_REQUEST_NOT_ONE_ENCODING\"}}"));
            };
            // A-F78: the re-gossip tick seals it again to a custodian that joins the vault before it settles
            rt.node_mut().peg_request_own_secret(&req.slot_key(), secret.clone());
            if is_custodian {
                rt.custodian_act_on_request(&req, now);
            }
            eprintln!(
                "[peg-in] REQUESTED a mint from this node (custodian here: {is_custodian}; sealed to {} custodian(s))",
                req.sealed.len()
            );
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"minted\":false,\"published\":false,\"mint_height\":{mint_height},\"outcome\":\"REQUESTED\",\"gathering\":true,\"attestations_gathered\":0}}"
                ),
            )
        }
        ("POST", "/register_wrapped_asset") => {
            // GOVERNANCE: register (or re-tune) a WRAPPED asset for the IonSwap bridge. `ratio_bps` = 15000 for a
            // volatile asset (wBTC/wETH — keeps the 150% volatility buffer) or 10000 for a vetted stablecoin (wDAI —
            // 1:1, EXEMPT from the buffer); clamped ≥10000 by the ledger so nothing registers sub-1:1. Seeds the
            // asset's confidential PSM + this custodian's per-asset opening at the genesis zero-value state. Loopback
            // control surface; mainnet gates this behind the bicameral governance vote (crate::governance).
            let asset_id = match json_num_field(body, "asset_id") {
                Some(a) => a as u32,
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let ratio_bps = json_num_field(body, "ratio_bps").unwrap_or(15_000) as u32;
            let epoch_id = json_num_field(body, "epoch_id").unwrap_or(0) as u64;
            // Attestors as a flat record concat: `pubkey_len(u16 LE) ‖ pubkey ‖ sig_len(u16 LE) ‖ sig` (hex)
            // — the SAME encoding every other threshold route on this surface accepts, parsed the same way.
            let ab = json_str_field(body, "attestors_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let mut attestors: Vec<crate::psm::MintAttestor> = Vec::new();
            let mut off = 0;
            while off + 2 <= ab.len() {
                let plen = u16::from_le_bytes([ab[off], ab[off + 1]]) as usize;
                off += 2;
                if off + plen + 2 > ab.len() {
                    break;
                }
                let pubkey = ab[off..off + plen].to_vec();
                off += plen;
                let slen = u16::from_le_bytes([ab[off], ab[off + 1]]) as usize;
                off += 2;
                if off + slen > ab.len() {
                    break;
                }
                let sig = ab[off..off + slen].to_vec();
                off += slen;
                attestors.push(crate::psm::MintAttestor { pubkey, sig });
            }
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⛔⛔⛔ THIS ROUTE NO LONGER SETS A RATIO — IT PUBLISHES AN OBJECT THE CHAIN DECIDES.
            //
            // It used to call `node.register_wrapped_asset(asset_id, ratio_bps)` directly, so the value a
            // socket supplied became the number this node minted against, while every other node derived a
            // different one from blocks. "Loopback only" bounded WHO could do it and changed nothing about
            // what it was: a consensus value set by local mutation — the root error that let a DEX fill's
            // local burn never travel. The ratio now rides a block as
            // `Class::WrappedAssetRegister`; `prev_ratio_bps` is read from THIS node's ledger so the
            // attestation commits to the exact transition, and the >=2/3 bonded tally runs at apply on
            // every node, not here.
            let prev_ratio_bps = rt.node().peg().wrapped_asset_ratio_bps(asset_id).unwrap_or(0);
            let header = crate::wrapped_asset_tx::WrappedAssetRegisterHeader {
                epoch_id,
                asset_id,
                prev_ratio_bps,
                ratio_bps,
            };
            let bits = rt.node().required_stamp_bits();
            let tx = crate::wrapped_asset_tx::as_pq_tx(&header, &attestors, bits);
            // ⛔ `submit_tx`, for the reason the faucet drip records above: pooling a chain object
            // without gossiping it makes its settlement a function of which node received the request.
            match rt.submit_tx(tx) {
                Ok(_) => (
                    200,
                    format!(
                        "{{\"status\":\"PUBLISHED\",\"asset_id\":{},\"prev_ratio_bps\":{},\"ratio_bps\":{}}}",
                        asset_id, prev_ratio_bps, ratio_bps
                    ),
                ),
                Err(e) => (200, err_json(&format!("PUBLISH_REFUSED:{e:?}"))),
            }
        }
        ("POST", "/wrapped_mint_execute") => {
            // ⭐ DB-77 — the wrapped mint rides the SAME request lane as the native peg-in (asset_id ≠ 0):
            // any node requests, the custodians propose from their per-asset openings, the object rides a
            // block and credits the note on every node. Before this the door minted LOCALLY on a
            // 1-of-1 executor and peers never credited the note.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let asset_id = match json_num_field(body, "asset_id") {
                Some(a) => a as u32,
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let deposit_id = match h32("deposit_id") {
                Some(a) => a,
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let deposit_value = json_num_field(body, "deposit_value").unwrap_or(0) as u128;
            let mint = json_num_field(body, "mint").unwrap_or(0) as u128;
            let note_payload = json_str_field(body, "note_payload")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let reserve_address = json_str_field(body, "reserve_address").unwrap_or_default();
            let mint_carrier = json_str_field(body, "mint_carrier_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // ⭐ DB-273 §19 L1: the credited note's OLI clue — the ONLY owner this door reads.
            let owner_clue = owner_clue_field(body);
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let mint_height = rt.node().tip_height();
            let key = crate::peg_attest::slot_key_for(asset_id, &deposit_id);
            let answer = |minted: bool, published: bool, outcome: &str, gathering: bool| -> String {
                format!(
                    "{{\"status\":\"OK\",\"asset_id\":{asset_id},\"minted\":{minted},\"published\":{published},\"mint_height\":{mint_height},\"outcome\":\"{outcome}\",\"gathering\":{gathering}}}"
                )
            };
            if asset_id == crate::peg::NATIVE_PEG_ASSET_ID || rt.node().peg().wrapped_asset_ratio_bps(asset_id).is_none() {
                return (200, answer(false, false, "BAD_REQUEST:ASSET", false));
            }
            if rt.node().peg().wrapped_deposit_minted(asset_id, &deposit_id) {
                return (200, answer(true, false, "ALREADY_MINTED", false));
            }
            if rt.node().wrapped_mint_is_published(&key) {
                return (200, answer(false, true, "CONFIDENTIAL_PUBLISHED", false));
            }
            if let Some(slot) = rt.node().peg_request_slot(&key) {
                let can_act_now = rt.bridge_signer().is_some() && slot.request.is_none();
                if !slot.done && !can_act_now {
                    return (200, answer(false, false, "GATHERING", true));
                }
            }
            let Some(owner_clue) = owner_clue else {
                return (200, answer(false, false, "BAD_REQUEST:OWNER", false));
            };
            // ⭐ DB-273 §17 condition 4: the recipient the quorum signs COMMITS to the clue, computed here.
            let recipient = crate::peg::peg_in_recipient(&deposit_id, &owner_clue);
            let Some(cm_limbs) = crate::spend_frontier::note_cm_of(&note_payload) else {
                return (200, answer(false, false, "BAD_REQUEST:NOTE", false));
            };
            let Ok(mint_u64) = u64::try_from(mint) else {
                return (200, answer(false, false, "BAD_REQUEST:AMOUNT", false));
            };
            if mint == 0 || deposit_value == 0 || reserve_address.is_empty() {
                return (200, answer(false, false, "BAD_REQUEST:FIELDS", false));
            }
            // DB-93: the deposit id is the function of the foreign deposit address (one mint per deposit).
            if deposit_id != crate::peg::deposit_id_for_reserve_address(&reserve_address) {
                return (200, answer(false, false, "BAD_REQUEST:DEPOSIT_ID_NOT_FROM_RESERVE_ADDRESS", false));
            }
            // DB-80b: like the native door — the requester commits its mint delta (`delta_commit` =
            // solvency_commit_256(mint, d_blind)), seals the blind, and proves the note opens to the committed
            // figure IN THE NAMED ASSET. The amount never rides a chain object; the asset does.
            let _ = mint_u64;
            let delta_commit = match json_str_field(body, "delta_commit").and_then(|h| hex_decode(&h)) {
                Some(b) => match <[u8; 32]>::try_from(b.as_slice()).ok().and_then(|a| crate::spend_frontier::cm_bytes_to_root(&a)) {
                    Some(d) => d,
                    None => return (200, answer(false, false, "BAD_REQUEST:DELTA_COMMIT", false)),
                },
                None => return (200, answer(false, false, "BAD_REQUEST:DELTA_COMMIT", false)),
            };
            let d_blind = match json_str_field(body, "d_blind_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b)) {
                Some(d) => d,
                None => return (200, answer(false, false, "BAD_REQUEST:D_BLIND", false)),
            };
            if delta_commit != crate::peg::PegLedger::mint_delta_commit(mint, d_blind) {
                return (200, answer(false, false, "BAD_REQUEST:DELTA_COMMIT_OPENING", false));
            }
            let asset_tag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(asset_id);
            if !usdm_decider::whir_rec_block::verify_asset_mint_validity_committed_bytes(&mint_carrier, cm_limbs, asset_tag, delta_commit) {
                return (200, answer(false, false, "BAD_REQUEST:MINT_CARRIER", false));
            }
            // §18.14: a coin note is funded like the bridge's own ledgers: the deposit's chain is the ledger's, the address the reserve's own for this blind, and a Bitcoin deposit
            // is co-signed (§BR-2). Every custodian re-checks all of it before it signs.
            let mut sweep = None;
            // SAFE AT SCALE: a coin deposit's address is under ONE vault's keys; its request is sealed to that vault's
            // custodians (every bonded custodian on a one-vault chain). Any other wrapped asset: every bonded custodian.
            let mut deposit_vault: Option<u32> = None;
            if crate::peg::PegLedger::is_coin_ledger(asset_id) {
                if !crate::peg::PegLedger::deposit_unit_matches(asset_id, &reserve_address) {
                    return (200, answer(false, false, "BAD_REQUEST:DEPOSIT_CHAIN", false));
                }
                sweep = match sweep_auth_from_json(body) {
                    Ok(a) => a,
                    Err(_) => return (200, answer(false, false, "BAD_REQUEST:SWEEP", false)),
                };
                deposit_vault = rt.node().vault_of_reserve_address(&reserve_address, &d_blind, sweep.as_ref().map(|a| &a.depositor_x));
                if deposit_vault.is_none() {
                    return (200, answer(false, false, "BAD_REQUEST:RESERVE_ADDRESS", false));
                }
            }
            let secret = crate::peg_attest::RequestSecret {
                value_a: deposit_value,
                value_b: mint,
                address: reserve_address.clone(),
                owner_clue,
                d_blind,
                pay_after: 0,
                sweep,
            };
            let mut sealed = Vec::new();
            let seal_to = match deposit_vault {
                Some(v) => rt.node().custodian_eks_of_vault(v),
                None => rt.node().validators().bonded_custodian_eks(),
            };
            for (id, ek) in seal_to {
                if let Some(blob) = crate::peg_attest::seal_request_to(&ek, &secret) {
                    sealed.push((id, blob));
                }
            }
            if sealed.is_empty() {
                return (200, answer(false, false, "NO_CUSTODIANS", false));
            }
            let mut req = crate::peg_attest::PegRequest {
                kind: crate::peg_attest::PEG_REQUEST_WRAPPED,
                asset_id,
                id: deposit_id,
                recipient,
                note_payload,
                carrier: mint_carrier,
                out0_cm: usdm_decider::poseidon2_compress::zero_digest(),
                out1_cm: usdm_decider::poseidon2_compress::zero_digest(),
                delta_commit,
                membership_carrier: Vec::new(),
                membership_tip: Vec::new(),
                leaf_commit: usdm_decider::poseidon2_compress::zero_digest(),
                sealed,
                stamp: 0,
                ticket: Vec::new(),
                epoch_ct: Vec::new(),
                unit: None,
            };
            req.stamp_to(rt.node().required_stamp_bits());
            if let Err(why) = rt.node().peg_request_verify_public(&req) {
                return (200, answer(false, false, &format!("BAD_REQUEST:{why}"), false));
            }
            let now = rt.now_unix_ms(); // DB-416: the runtime's one clock
            let is_custodian = rt.bridge_signer().is_some();
            // DB-402 R4: note what every peer decodes from the published bytes (one encoding)
            let Some(req) = rt.publish_peg_request(&req, now) else {
                return (200, answer(false, false, "BAD_REQUEST:PEG_REQUEST_NOT_ONE_ENCODING", false));
            };
            // A-F78: the re-gossip tick seals it again to a custodian that joins the vault before it settles
            rt.node_mut().peg_request_own_secret(&req.slot_key(), secret.clone());
            if is_custodian {
                rt.custodian_act_on_request(&req, now);
            }
            eprintln!(
                "[wrapped-mint] REQUESTED a wrapped mint (asset {asset_id}) from this node (custodian here: {is_custodian}; sealed to {} custodian(s))",
                req.sealed.len()
            );
            (200, answer(false, false, "REQUESTED", true))
        }
        ("POST", "/defi_claim_member_leg") => {
            // ⭐ §BR-15 — A DeFi CLAIM'S MEMBER LEG at this node's NEWEST ring root (`Node::member_leg_for_note`): a DeFi claim is
            // carried into the next block at once (the fold door accepts any root of its ring), so it never waits for an epoch
            // anchor — the cash-out claim's anchor exists because that claim waits hours for its batch. NOT_YET only until the
            // leaf's record has folded here (one fold step after its settlement).
            // DIGITAL-CASH-PRIVACY-REVIEWED: answered to this node's own wallet over loopback; nothing is stored or gossiped.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let (Some(cm), Some(nf), Some(blind)) = (
                h32("cm_hex"),
                h32("claim_nullifier"),
                json_str_field(body, "blind_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b)),
            ) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&nf) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐ A-F25 (2026-11-11): EPOCH ANCHOR ONLY — the ring-root path is removed. A DeFi object's leg must
            // survive until its batch settles (25–40 min); the ring (64 steps, ~13 min) ages out and the fold
            // refuses it on a peer that folded past it. The epoch anchor is kept ~26 h, which covers every batch
            // wait. NOT_YET until the next anchor (≤ 10 min of chain time) holds the note — the wallet retries.
            // BORROWED: Zcash wallets' anchor depth (never the newest).
            let leg = rt
                .node()
                .member_leg_at_epoch_anchor(&cm, binder, blind)
                .map(|(c, t, l, _)| (c, t, l));
            match leg {
                Ok((carrier, tuple, leaf_commit)) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"membership_carrier_hex\":\"{}\",\"membership_tip_hex\":\"{}\",\"leaf_commit_hex\":\"{}\"}}",
                        hex_encode(&carrier),
                        hex_encode(&tuple),
                        hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(leaf_commit))
                    ),
                ),
                Err(why) => (200, format!("{{\"status\":\"NOT_YET\",\"why\":\"{why}\"}}")),
            }
        }
        ("POST", "/claim_member_leg") => {
            // ⭐ §19.4 — A CASH-OUT CLAIM'S MEMBER LEG for this node's own wallet: the staged piece's record-free membership,
            // anchored to the newest EPOCH ANCHOR this node folded (`Node::member_leg_at_epoch_anchor`), so the claim the
            // wallet relays now still verifies at its batch. NOT_YET while no anchor holds the note (≤ 10 min after it folds).
            // DIGITAL-CASH-PRIVACY-REVIEWED: answered to this node's own wallet over loopback; nothing is stored or gossiped.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let (Some(cm), Some(nf), Some(blind)) = (
                h32("cm_hex"),
                h32("usdm_nullifier"),
                json_str_field(body, "blind_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b)),
            ) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&nf) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            // A FAST claim (pay-after 0) folds at once, inside the ring every node holds, so it anchors to the newest ring root
            // like an escrowed piece's leg (`/defi_claim_member_leg`) instead of waiting up to `peg::EPOCH_ANCHOR_MS` of chain
            // time for an anchor that only a delayed batch needs. The door accepts either (`member_leg_object_verdict`).
            let leg = if json_num_field(body, "pay_after") == Some(0) {
                rt.node().member_leg_for_note(&cm, binder, blind).map(|(c, t, l)| (c, t, l, 0))
            } else {
                rt.node().member_leg_at_epoch_anchor(&cm, binder, blind)
            };
            match leg {
                Ok((carrier, tuple, leaf_commit, ordinal)) => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"membership_carrier_hex\":\"{}\",\"membership_tip_hex\":\"{}\",\"leaf_commit_hex\":\"{}\",\"anchor_ordinal\":{ordinal}}}",
                        hex_encode(&carrier),
                        hex_encode(&tuple),
                        hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(leaf_commit))
                    ),
                ),
                Err(why) => (200, format!("{{\"status\":\"NOT_YET\",\"why\":\"{why}\"}}")),
            }
        }
        ("POST", "/peg_out_ticket") => {
            // ⭐ §BR-5 — BUILD A CASH-OUT PIECE'S TICKET for this node's own wallet, BEFORE it proves its burn: the destination,
            // pay-after and redeem blind under a fresh ticket key encapsulated ONCE to the final key of the piece's epoch (§BR-9a
            // step c); each custodian's sealed envelope holds only the destination KIND, the leg blind its opening advances by,
            // the burn amount and the change's clue. Returns the ticketed commitment (the wallet binds its burned output to it) and the parts.
            // DIGITAL-CASH-PRIVACY-REVIEWED: answered to this node's own wallet over loopback; nothing is stored or gossiped
            // here (the request carries the parts once the burn is proven).
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let (Some(usdm_nullifier), Some(redeem_to), Some(burn_amount), Some(owner_clue)) = (
                h32("usdm_nullifier"),
                json_str_field(body, "redeem_to").filter(|a| !a.is_empty()),
                json_num_field(body, "burn_amount").filter(|b| *b > 0),
                json_str_field(body, "note_clue_hex").and_then(|h| hex_decode(&h)).filter(|c| !c.is_empty()),
            ) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let pay_after = json_num_field(body, "pay_after").unwrap_or(0);
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            if pay_after > rt.node().chain_time_ms().saturating_add(crate::peg::PAY_AFTER_MAX_MS) {
                return (200, err_json("PAY_AFTER_PAST_CAP"));
            }
            // SAFE AT SCALE: a cash-out is paid by ONE vault, so its ticket's envelopes are sealed to that vault's custodians —
            // every bonded custodian on a one-vault chain, as it was; sixteen at most on any chain. The vault is the wallet's
            // `vault` when it names one (it offers the burn to the next vault when the first does not hold the release),
            // else the first vault the burn's nullifier routes to (`Node::first_payout_vault`).
            let vault = json_num_field(body, "vault").and_then(|v| u32::try_from(v).ok()).unwrap_or_else(|| rt.node().first_payout_vault(&usdm_nullifier));
            let custodians = rt.node().custodian_eks_of_vault(vault);
            if custodians.is_empty() {
                return (200, err_json("NO_CUSTODIANS"));
            }
            // §BR-9a step (c): the ticket key is encapsulated ONCE to the final key of the piece's epoch
            // ⭐ §18.14: a coin sell does not wait for a future hour: its ticket seals to the key custody already holds (the one orders seal to), so the payout starts as soon as the burn folds.
            // Cons: custody reads the destination at the burn, not at its epoch's batch. A dollar cash-out keeps its batch.
            // A FAST dollar cash-out (pay-after 0: the user turned Auto-OPSEC off through its warning) is due at once
            // (`Node::cash_out_batch_due`), so it seals to the released key the same way: a future epoch's key would hold it
            // until that epoch ends (MEASURED 2026-11-08, real nodes at their real rate of about 5 blocks a minute: epoch 2 ends
            // at blue score 21,600, about 72 hours in, against a payout the user asked for now). Cons: none beyond what
            // the fast switch already states — its burn and payout are adjacent either way.
            let ek = rt.node().peg().epoch_keys();
            let sealed_to = if json_num_field(body, "coin").is_some_and(|c| c == 1) || pay_after == 0 {
                ek.release_epoch().and_then(|e| ek.release_key(e).map(|pk| (e, pk)))
            } else {
                ek.sealing_epoch(pay_after)
            };
            let Some((_epoch, pk)) = sealed_to else {
                return (200, err_json("NO_EPOCH_KEY_YET"));
            };
            let (Some(m), Some(leg_blind)) = (
                crate::cashout_ticket::fresh_entropy(32).and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok()),
                usdm_decider::whir_rec_block::fresh_lc_blind(),
            ) else {
                return (200, err_json("NO_ENTROPY"));
            };
            let redeem_blind = rt.node().redeem_blind_for(&usdm_nullifier);
            let Some((_key, epoch_ct, ticket, ticketed)) =
                crate::epoch_release::seal_ticket(&pk, &m, redeem_to.as_bytes(), pay_after, &redeem_blind)
            else {
                return (200, err_json("TICKET"));
            };
            let monero = crate::bridge::is_monero_address(&redeem_to);
            // ⭐ §18.14: a coin note's burn names its coin kind in the sealed slot; it pays from its own ledger
            let coin_burn = json_num_field(body, "coin").is_some_and(|c| c == 1);
            let slot = match (coin_burn, monero) {
                (true, true) => crate::cashout_ticket::KIND_COIN_XMR.to_string(),
                (true, false) => crate::cashout_ticket::KIND_COIN_BTC.to_string(),
                (false, _) => crate::cashout_ticket::request_slot(monero),
            };
            let mut envelopes = Vec::new();
            for (id, ek) in &custodians {
                let secret = crate::peg_attest::RequestSecret {
                    value_a: u128::from(burn_amount),
                    value_b: u128::from(burn_amount),
                    address: slot.clone(),
                    owner_clue: owner_clue.clone(),
                    d_blind: leg_blind,
                    pay_after,
                    sweep: None,
                };
                match crate::peg_attest::seal_request_to(ek, &secret) {
                    Some(blob) => envelopes.push((*id, blob)),
                    None => return (200, err_json("SEAL")),
                }
            }
            let parts: crate::peg_out_tx::TicketParts = (ticket, envelopes, epoch_ct);
            let bytes = postcard::to_allocvec(&parts).unwrap_or_default();
            (
                200,
                // the leg blind goes back to this node's own wallet only: its burned output's opening needs it (and the request
                // door re-checks the binding with it); it is never published
                format!(
                    "{{\"status\":\"OK\",\"ticketed_commit\":\"{}\",\"ticket_parts_hex\":\"{}\",\"leg_blind_hex\":\"{}\"}}",
                    hex_encode(&ticketed),
                    hex_encode(&bytes),
                    hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&leg_blind))
                ),
            )
        }
        ("POST", "/peg_out_execute") => {
            // ⭐ DB-77 — THE REDEEM IS A REQUEST, ON ANY NODE (Liquid: a peg-out is an ordinary transaction
            // any node relays; the functionaries act on chain state). The wallet's own node verifies the
            // whole burn (membership cross-bind, deletion witness, the burn carrier at the stated amount),
            // seals the amount / payout address / owner keys per custodian, records the request and
            // gossips it. The custodians propose, attest and publish `Class::PegOut`; the block burns the
            // note and credits the change on every node. A poll answers chain state first.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let usdm_nullifier = match h32("usdm_nullifier") {
                Some(a) => a,
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let cm_field = |k: &str| -> Result<crate::spend_frontier::Digest4, ()> {
                match h32(k) {
                    None => Ok(usdm_decider::poseidon2_compress::zero_digest()),
                    Some(b) => crate::spend_frontier::cm_bytes_to_root(&b).ok_or(()),
                }
            };
            let (Ok(out0_cm), Ok(out1_cm)) = (cm_field("out0_cm"), cm_field("out1_cm")) else {
                return (200, err_json("BAD_FIELDS"));
            };
            let burn_carrier = json_str_field(body, "burn_carrier_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let burn_amount = json_num_field(body, "burn_amount").unwrap_or(0) as u128;
            let change_note = json_str_field(body, "change_note_payload")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let redeem_to = json_str_field(body, "redeem_to").unwrap_or_default();
            // §BR-1: the piece's privacy delay — the earliest chain height it may be paid at, the wallet's own draw inside
            // [next batch, 24 h]. Absent or zero = the next payout batch (the "fast, less private" switch).
            let pay_after = json_num_field(body, "pay_after").unwrap_or(0) as u64;
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⭐ A-F114: every call (the first and each poll) may carry the spender's fresh wrappers; the node keeps the
            // freshest for the claim it publishes later (`Node::canon_held_wrappers`)
            if let Some(w) = crate::canon_chain::spender_wrappers() {
                rt.node_mut().canon_hold_wrappers(usdm_nullifier, w);
            }
            let answer = |redeemed: bool, published: bool, outcome: &str, gathering: bool, gathered: usize| -> String {
                format!(
                    "{{\"status\":\"OK\",\"redeemed\":{redeemed},\"published\":{published},\"outcome\":\"{outcome}\",\"gathering\":{gathering},\"attestations_gathered\":{gathered}}}"
                )
            };
            if rt.node().peg().burn_redeemed(&usdm_nullifier) {
                return (200, answer(true, false, "ALREADY_REDEEMED", false, 0));
            }
            if rt.node().peg_out_is_published(&usdm_nullifier) {
                return (200, answer(false, true, "CONFIDENTIAL_PUBLISHED", false, 0));
            }
            let gathered = rt.node().peg_out_attestations_for(&usdm_nullifier).len();
            if let Some(slot) = rt.node().peg_request_slot(&usdm_nullifier) {
                let can_act_now = rt.bridge_signer().is_some() && slot.request.is_none();
                if !slot.done && !can_act_now {
                    return (200, answer(false, false, "GATHERING", true, gathered));
                }
            }
            // ⭐ DB-273 §19 L1: the change note's OLI clue — the ONLY owner this door reads.
            let Some(owner_clue) = owner_clue_field(body) else {
                eprintln!("[peg-out] ⛔ BAD_REQUEST at gate {}: {}", 1, "owner");
                return (200, answer(false, false, "BAD_REQUEST:OWNER", false, 0));
            };
            let mem_carrier = json_str_field(body, "membership_carrier_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let mem_tip = json_str_field(body, "membership_tip_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let Some(leaf_commit) = h32("membership_leaf_commit").and_then(|b| crate::spend_frontier::cm_bytes_to_root(&b)) else {
                eprintln!("[peg-out] ⛔ BAD_REQUEST at gate {}: {}", 4, "membership leaf commit");
                return (200, answer(false, false, "BAD_REQUEST:MEMBERSHIP", false, 0));
            };
            if burn_amount == 0 || redeem_to.is_empty() || change_note.len() < 32 {
                return (200, answer(false, false, "BAD_REQUEST:FIELDS", false, 0));
            }
            if pay_after > rt.node().chain_time_ms().saturating_add(crate::peg::PAY_AFTER_MAX_MS) {
                return (200, answer(false, false, "BAD_REQUEST:PAY_AFTER_PAST_CAP", false, 0));
            }
            // §19.4: the burn is ONE rung of the cash-out ladder, released in the paying ledger's own unit at its reference
            // price (satoshis from the native ledger, piconero from Monero's) — refused HERE, before anything is burned
            // ⭐ §18.14: a coin note's burn is one rung of its own coin's ladder, atom for atom
            let coin_burn = json_num_field(body, "coin").is_some_and(|c| c == 1);
            let coin_asset = if !coin_burn {
                crate::peg::NATIVE_PEG_ASSET_ID
            } else if crate::bridge::is_monero_address(&redeem_to) {
                crate::peg::COIN_XMR_ASSET_ID
            } else {
                crate::peg::COIN_BTC_ASSET_ID
            };
            if coin_burn {
                if !u64::try_from(burn_amount).is_ok_and(|b| crate::peg_pool::coin_denoms(coin_asset).contains(&b)) {
                    return (200, answer(false, false, "BAD_REQUEST:NOT_A_LADDER_PIECE", false, 0));
                }
            } else {
                if !u64::try_from(burn_amount).is_ok_and(crate::peg_pool::is_usd_denom) {
                    return (200, answer(false, false, "BAD_REQUEST:NOT_A_LADDER_PIECE", false, 0));
                }
                if rt.node().peg().peg_out_release(burn_amount, &redeem_to).is_none() {
                    return (200, answer(false, false, "BAD_REQUEST:NO_PRICE_MARK", false, 0));
                }
            }
            // ⛔ DB-121 (owner 2026-09-21): a burn is refused unless its destination is one the reserve's custody
            // can PAY — a Bitcoin address on THIS node's Bitcoin network (the payout lane pays exactly what
            // `script_pubkey_for_address` decodes); a Monero address once the Monero custody signer is live
            // (DB-121x). Without this the burn would destroy the USDm and leave the lane an obligation it can
            // never settle — the redeemer paid nothing, on testnet exactly as on mainnet.
            match crate::btc_tx::script_pubkey_for_address(redeem_to.trim()) {
                Some((net, _)) if net == crate::bridge::btc_net() => {}
                Some(_) => return (200, answer(false, false, "BAD_REQUEST:REDEEM_TO_OTHER_BITCOIN_NETWORK", false, 0)),
                None => {
                    // DB-121x: a Monero destination is payable once the bonded set's custody wallet exists (its
                    // address is known to this node) and the address is on this node's Monero network.
                    let xmr_live = rt.node().xmr_custody_address_current().is_some();
                    match crate::bridge::xmr_address_net(redeem_to.trim()) {
                        Some(net) if net == crate::bridge::xmr_net_byte() && xmr_live => {}
                        Some(net) if net == crate::bridge::xmr_net_byte() => return (200, answer(false, false, "BAD_REQUEST:XMR_CUSTODY_NOT_LIVE", false, 0)),
                        Some(_) => return (200, answer(false, false, "BAD_REQUEST:REDEEM_TO_OTHER_MONERO_NETWORK", false, 0)),
                        None => return (200, answer(false, false, "BAD_REQUEST:REDEEM_TO_UNPAYABLE", false, 0)),
                    }
                }
            }
            eprintln!(
                "[peg-out] request: owner=true membership={} spends_field=true burn_carrier={}B change_note={}B",
                !mem_carrier.is_empty(),
                burn_carrier.len(),
                change_note.len()
            );
            // ⭐ §BR-5 — THE CASH-OUT TICKET, built by this node at `/peg_out_ticket` before the wallet proved its burn, comes
            // back with the burn: the ticketed commitment and the ticket's parts. The burn carrier's burned output must open
            // under that commitment (`cashout_ticket::burn_out_cm`) — the owner's own proof fixes the destination, so a copy of
            // this request carrying another ticket is refused here and at every custodian.
            let (Some(ticketed), Some(parts), Some(leg_blind)) = (
                h32("ticketed_commit"),
                json_str_field(body, "ticket_parts_hex")
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| crate::chain_object::decode_exact::<crate::peg_out_tx::TicketParts>(&b))
                    .filter(crate::peg_out_tx::ticket_parts_well_formed),
                json_str_field(body, "leg_blind_hex").and_then(|h| hex_decode(&h)).and_then(|b| crate::spend_frontier::digest_from_lane_bytes(&b)),
            ) else {
                return (200, answer(false, false, "BAD_REQUEST:TICKET", false, 0));
            };
            if u64::try_from(burn_amount).map(|b| crate::cashout_ticket::burn_out_cm_of(if coin_burn { coin_asset } else { 0 }, b, &ticketed, &leg_blind)) != Ok(out0_cm) {
                return (200, answer(false, false, "BAD_REQUEST:BURN_NOT_BOUND_TO_TICKET", false, 0));
            }
            let (ticket, sealed, epoch_ct) = parts;
            if sealed.is_empty() {
                return (200, answer(false, false, "NO_CUSTODIANS", false, 0));
            }
            let mut req = crate::peg_attest::PegRequest {
                kind: crate::peg_attest::PEG_REQUEST_OUT,
                asset_id: coin_asset,
                id: usdm_nullifier,
                recipient: ticketed, // §BR-5: the ticketed redeem commitment the quorum signs
                note_payload: change_note,
                carrier: burn_carrier,
                out0_cm,
                out1_cm,
                delta_commit: usdm_decider::poseidon2_compress::zero_digest(),
                membership_carrier: mem_carrier,
                membership_tip: mem_tip,
                leaf_commit,
                sealed,
                stamp: 0,
                ticket,
                epoch_ct,
                unit: None,
            };
            req.stamp_to(rt.node().required_stamp_bits());
            if let Err(why) = rt.node().peg_out_request_verify_full(&req, burn_amount, &leg_blind) {
                eprintln!("[peg-out] ⛔ BAD_REQUEST at the request door: {why}");
                return (200, answer(false, false, &format!("BAD_REQUEST:{why}"), false, 0));
            }
            let now = rt.now_unix_ms(); // DB-416: the runtime's one clock
            let is_custodian = rt.bridge_signer().is_some();
            // DB-402 R4: note what every peer decodes from the published bytes (one encoding)
            // ⭐ §19.4: a claim relayed at its wallet's drawn moment (`relay_after_ms`, capped at the 24 h pay-after reach)
            // (absent = relay at once, the pre-§19.4 behaviour every other request keeps)
            let relay_after_ms = json_num_field(body, "relay_after_ms").map_or(0, |ms| ms.min(now.saturating_add(86_400_000)));
            let Some(req) = rt.publish_peg_request_at(&req, now, relay_after_ms) else {
                return (200, answer(false, false, "BAD_REQUEST:PEG_REQUEST_NOT_ONE_ENCODING", false, 0));
            };
            if is_custodian {
                rt.custodian_act_on_request(&req, now);
            }
            eprintln!(
                "[peg-out] REQUESTED a redeem from this node (custodian here: {is_custodian}; sealed to {} custodian(s))",
                req.sealed.len()
            );
            (200, answer(false, false, "REQUESTED", true, 0))
        }
        ("POST", "/authorize_reserve_move") => {
            // Reserve-movement authorization (the bond-weighted multisig tally, the PQ-secure overlay): verify a ≥2/3 POST-QUANTUM threshold
            // certificate over the movement statement BEFORE any (classical, home-chain) foreign signature is
            // produced. The Bitcoin payout lane (`btc_payout`: each custodian's own independent BIP-340 signature) runs ONLY on `authorized:true`; fail-closed on any
            // bad / sub-threshold / wrong-statement certificate. `statement_hex` is the exact
            // `bond_tally::reserve_move_statement` bytes the bonded quorum threshold-signed.
            let statement = json_str_field(body, "statement_hex")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let cert = crate::bond_tally::PqThresholdCert {
                attestors: parse_peg_attestors(
                    &json_str_field(body, "attestors_hex")
                        .and_then(|h| hex_decode(&h))
                        .unwrap_or_default(),
                ),
            };
            let rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let authorized = rt.node().authorize_reserve_move(&statement, &cert);
            (
                200,
                format!("{{\"status\":\"OK\",\"authorized\":{authorized}}}"),
            )
        }
        ("POST", "/reserve_release_status") => {
            // ⭐ DB-121 (2026-09-20) — READ-ONLY. The door that stood here (`/authorize_reserve_release`) set a
            // burn's `released` flag on request, with nothing paid: the record of a release that had not
            // happened (DB-114 found the two-quorum shape; DB-121 found that NO code could sign the Bitcoin
            // transaction at all). A release is now recorded ONLY by the Bitcoin payout lane
            // (`crate::btc_payout`), when this node's OWN Bitcoin source has watched the payout confirm — the
            // deposit watcher's shape, one edge over. This door only reports what the chain and that lane hold.
            // DIGITAL-CASH-PRIVACY-REVIEWED: by construction the reply is the fixed three-boolean shape
            // `{status, burned, payout_pending, released}` about a nullifier the caller already holds — the
            // format string below has no amount, address, key or owner field to fill.
            let h32 = |k: &str| -> Option<[u8; 32]> {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            };
            let burn_nullifier = match h32("usdm_nullifier") {
                Some(a) => a,
                _ => return (200, err_json("BAD_FIELDS")),
            };
            let rt = match rt.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let burned = rt.node().peg().is_burned(&burn_nullifier);
            let pending = rt.node().reserve_release_pending(&burn_nullifier);
            // CACHE-ONLY: a read-only count of the payout proposals this node is tracking (DB-121 Bitcoin lane slots
            // plus DB-121x Monero lane slots), reported so a waiting wallet can tell "being signed" from "waiting
            // for confirmations"; it decides nothing — the release itself is settled only when this node's own
            // Bitcoin source or Monero wallet sees the payout confirm.
            let in_flight = rt.payout_lane().proposals_in_flight() + rt.xmr_payout_lane().proposals_in_flight();
            (
                200,
                format!(
                    "{{\"status\":\"OK\",\"burned\":{burned},\"payout_pending\":{pending},\"proposals_in_flight\":{in_flight},\"released\":{}}}",
                    burned && !pending
                ),
            )
        }
        ("POST", "/slash_reserve_theft") => {
            // ⛔ DB-274 P4b (§8.15) — REPORT A RESERVE THEFT: DB-334's `/report_equivocation` shape. This route PUBLISHES
            // the evidence and slashes NOTHING here. The block that carries it slashes the named offenders at its fold,
            // on every node (`theft_tx::apply_chain_reserve_theft`), weighed against that step's pre-state set.
            // It used to slash on THIS node alone, over an offender list no signature covered. Now the ≥2/3
            // certificate signs the statement AND the offenders (`theft_tx::theft_msg`). `offenders_hex` is a concat of
            // 32-byte ids; the publisher puts them in their one canonical order.
            // DIGITAL-CASH-PRIVACY-REVIEWED: the evidence is a public validator object the block's bond set carries;
            // the answer is the outcome alone — never a key, an id or an amount.
            let field = |k: &str| json_str_field(body, k).and_then(|h| hex_decode(&h));
            let (Some(statement), Some(attestors), Some(raw)) =
                (field("statement_hex"), field("attestors_hex"), field("offenders_hex"))
            else {
                return (200, err_json("BAD_FIELDS"));
            };
            if raw.is_empty() || raw.len() % 32 != 0 {
                return (200, err_json("BAD_OFFENDERS")); // a partial id is refused, never silently dropped
            }
            let offenders: Vec<[u8; 32]> =
                raw.chunks_exact(32).filter_map(|c| <[u8; 32]>::try_from(c).ok()).collect();
            let cert = crate::bond_tally::PqThresholdCert { attestors: parse_peg_attestors(&attestors) };
            // §BR-3 17.5: the stolen sats (a public Bitcoin fact) custody signed inside the v3 message
            let Some(loss_sats) = json_num_field(body, "loss_sats").filter(|l| *l > 0) else {
                return (200, err_json("BAD_LOSS"));
            };
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let outcome = rt.node_mut().publish_reserve_theft(&statement, &cert, &offenders, loss_sats);
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The evidence was admitted to the pool and \
                     travels until a block carries it; the named offenders are slashed at that block's fold on every \
                     node.\"}"
                        .to_string(),
                ),
                A::Refused(why) => (
                    422,
                    format!("{{\"status\":\"ERROR\",\"error\":\"THEFT_EVIDENCE_REFUSED\",\"detail\":\"{why}\"}}"),
                ),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/report_equivocation") => {
            // ⭐ DB-334 — REPORT A DOUBLE-SIGN. BORROWED-FROM: the Ethereum Beacon API's
            // `POST /eth/v1/beacon/pool/attester_slashings` — anyone submits the two conflicting signed messages, the
            // node verifies them, pools the evidence and relays it, and the slash happens at block processing on every
            // node (`equivocation_tx::apply_chain_equivocation`), never here. The publication is the node's own
            // (`Node::publish_equivocation`) — the SAME one its vote door takes when it catches a conflict — so there is
            // one publication, not two; DB-335's marking door gossips it until a block carries it.
            // §9.6 (docs/DB-334): `proves_equivocation` runs here, at the pool door and at graft; the object mints
            // nothing; its encoding is canonical and the pool deduplicates it; a vote wider than 16 KiB is refused.
            // DIGITAL-CASH-PRIVACY-REVIEWED: the evidence is a public validator object the block's bond set carries;
            // the answer is the outcome alone — never a key, an id, a block id or an amount.
            let cert = |k: &str| {
                json_str_field(body, k)
                    .and_then(|h| hex_decode(&h))
                    .filter(|b| b.len() <= crate::equivocation_tx::EQUIVOCATION_WIRE_MAX)
                    .and_then(|b| crate::validator::VoteCert::from_wire(&b))
            };
            let (Some(a), Some(b)) = (cert("vote_a_hex"), cert("vote_b_hex")) else {
                return (200, err_json("BAD_VOTES"));
            };
            let outcome = rt.lock().unwrap_or_else(|e| e.into_inner()).node_mut().publish_equivocation(&a, &b);
            use crate::node::AssetSpendOutcome as A;
            match outcome {
                A::Published => (
                    200,
                    "{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"detail\":\"The evidence was admitted to the pool and travels until a block carries it. The validator is slashed on every node when that block grafts, not now.\"}".to_string(),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"EQUIVOCATION_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/unbond_validator") => {
            // UNBOND (withdraw): remove the validator's bond weight from the set. Authenticated by an ML-DSA
            // signature over the v2 unbond statement (`pqauth::validator_unbond_msg`: validator, live bonding, owner) —
            // only the key-holder can unbond their own weight, and only the bonding it names.
            let pubkey = json_str_field(body, "pubkey")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            let sig = json_str_field(body, "sig")
                .and_then(|h| hex_decode(&h))
                .unwrap_or_default();
            // ⭐ DB-273 §19.3 L2: the returned bond's OLI clue — the ONLY owner this door reads. Without it the node
            // refuses: a returned bond filed nowhere a seed restore looks is money its owner cannot find.
            let credit_owner = owner_clue_field(body);
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            // ⛔⛔⛔ §AS — THIS PUBLISHES THE UNBOND; IT NO LONGER RELEASES IT LOCALLY.
            //
            // It used to call `rt.unbond_validator(..)`, which removed the weight and returned the note on
            // THIS node and told nobody. MEASURED: `A freed=Some(50000) | A weight=0 | B weight=50000` —
            // every peer kept counting the validator's full weight in the ≥2/3 denominator and kept its
            // bonded note locked, so the same bond was returnable once per node.
            //
            // ⭐ The release now happens when a block carrying the object grafts, on EVERY node including
            // this one. The answer says PUBLISHED, not unbonded, because a step is not an arrival.
            let Some(owner_clue) = credit_owner else {
                return (422, err_json("UNBOND_NEEDS_AN_OWNER"));
            };
            // ⭐ DB-272 — `own`: unbond THIS node's validator identity, signed by its vote key (the key a wallet's bond
            // sits under). Loopback-only like every route here; the caller chooses only where the note is filed.
            let outcome = if json_bool_field(body, "own").unwrap_or(false) {
                let (vote_pk, vote_sk) = crate::validator::load_or_create_node_vote_key();
                if crate::validator::vote_key_locked() {
                    return (422, err_json("VALIDATOR_IDENTITY_LOCKED"));
                }
                rt.node_mut().publish_own_unbond(&vote_pk, &vote_sk, &owner_clue)
            } else {
                // DB-258d: an externally signed unbond names the nonce it signed (its one-shot right's freshness).
                match json_str_field(body, "nonce_hex")
                    .and_then(|h| hex_decode(&h))
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                {
                    Some(nonce) => rt.node_mut().publish_unbond(&pubkey, &sig, &owner_clue, nonce),
                    None => return (422, err_json("UNBOND_NEEDS_ITS_SIGNED_NONCE")),
                }
            };
            use crate::node::AssetSpendOutcome as A;
            // DB-274 P2 (§8.7): the weight leaves when the unbond's block folds; the collateral stays slashable for the
            // unbonding window after that, then returns to its owner. The answer names that wait so the wallet can
            // show it honestly. A-F60: the wait is two gates on two clocks — the evidence horizon in blocks and the governed
            // window as a time on the chain's clock — and the answer names both, never one as the other at an assumed pace.
            let horizon = rt.node().unbond_horizon_blue();
            let window_ms = rt.node().unbond_ticks().saturating_mul(crate::dag::MESH_TARGET_SPACING_MS);
            let days = window_ms / crate::params::DAY_MS;
            match outcome {
                A::Published => (
                    200,
                    format!(
                        "{{\"status\":\"OK\",\"verdict\":\"PUBLISHED\",\"collateral_returns_after_blocks\":{horizon},\"collateral_returns_after_chain_ms\":{window_ms},\"detail\":\"The unbond was admitted to the pool and will travel. The weight is removed on every node when its block folds; the bonded collateral stays slashable for at least {horizon} blocks and {days} days on the chain's clock after that, then returns to its owner, not now.\"}}"
                    ),
                ),
                A::Refused(why) => (422, format!("{{\"status\":\"ERROR\",\"error\":\"UNBOND_REFUSED\",\"detail\":\"{why}\"}}")),
                A::NotPublished => (503, err_json("NOT_PUBLISHED")),
                A::Pending => asset_pending_answer(),
            }
        }
        ("POST", "/get_pq_epoch_address") | ("GET", "/get_pq_epoch_address") => {
            // The per-epoch confidential-fee TARGET as a REAL PQ stealth address (crate::address), which a
            // wallet decodes (B ‖ ML-KEM ek) and addresses its fee output (out3) to. PER-NODE derived
            // (decentralization pillar): each node returns its OWN fee address from its own fee seed + ML-KEM
            // key, so out3 fees collect to — and are redistributed by — the node the user runs, NEVER one
            // shared fee key. Deterministic in the current epoch, so the target a wallet fetches equals the one
            // the acceptance gate checks. Opaque (no amount/identity). Fail-closed to an explicit status if the
            // address can't be formed, so the wallet surfaces "unavailable" rather than a carrier it would reject.
            let mut rt = rt.lock().unwrap_or_else(|e| e.into_inner());
            let blue_score = match rt.rpc(RpcRequest::GetTip) {
                RpcResponse::Tip { blue_score, .. } => blue_score,
                _ => 0,
            };
            let (epoch, addr, b_hex) = rt.node().epoch_fee_address(blue_score);
            if addr.is_empty() {
                (200, err_json("PQ_EPOCH_ADDR_UNAVAILABLE"))
            } else {
                (200, format!(
                    "{{\"status\":\"OK\",\"epoch\":{},\"epoch_address\":\"{}\",\"epoch_b_hex\":\"{}\"}}",
                    epoch, addr, b_hex
                ))
            }
        }
        _ => (404, err_json("NOT_FOUND")),
    }
}

// ── HTTP/1.1 read: request line + headers + Content-Length body (loopback, trusted-local, small). ──
/// ⭐ THE ONE REQUEST-BODY CAP for every local HTTP door (this RPC and `sovereign::SovereignServer`, whose write routes
/// forward their body here): 8 MiB. The largest legitimate body is a framed object with its validity carrier (a proof
/// ≤ 1.8 MB plus notes and hex expansion), so nothing honest is refused; a body above it is refused before it is read in
/// full. MEASURED 2026-10-04 (surface census, "bounded work" column): the sovereign door read `Content-Length` bytes with
/// NO bound — a local client declaring 10^12 grew the buffer without limit (T3 exhaustion) — and this RPC's literal
/// `8 * 1024 * 1024` was the only cap in the tree. One constant, two readers (§9.5).
pub const RPC_BODY_MAX: usize = 8 * 1024 * 1024;

fn read_request(s: &mut TcpStream) -> Option<(String, String, String, crate::local_origin::RequestOrigin)> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 256 * 1024 {
            return None;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let header_txt = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = header_txt.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut content_len = 0usize;
    for l in lines {
        if let Some(v) = l.split_once(':') {
            if v.0.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.1.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
    while body.len() < content_len {
        if body.len() > RPC_BODY_MAX {
            return None;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len.min(body.len()));
    let from = crate::local_origin::RequestOrigin::from_head(&header_txt);
    Some((method, path, String::from_utf8_lossy(&body).to_string(), from))
}

/// Process-wide Letter state — the node's own ML-KEM identity (self-custodial; the decapsulation secret never
/// leaves here) + the metadata-blind relay ring. Lazily initialised on first Letter request.
static LETTER: std::sync::OnceLock<
    std::sync::Mutex<(crate::letter::LetterIdentity, crate::letter::LetterRelay)>,
> = std::sync::OnceLock::new();
type LetterState = std::sync::Mutex<(crate::letter::LetterIdentity, crate::letter::LetterRelay)>;
fn letter_state() -> &'static LetterState {
    #[cfg(test)]
    if let Some(dir) = crate::persist::thread_node_dir_for_test() {
        return letter_state_of_simulated_process(dir);
    }
    LETTER.get_or_init(new_letter_state)
}

/// This node's own letter key pair, `(encapsulation key, secret)`: what a Veil payment notice is sealed to and opened
/// with (`veil_lane`). The secret never leaves this process.
pub(crate) fn letter_identity_keys() -> (Vec<u8>, Vec<u8>) {
    let g = letter_state().lock().unwrap_or_else(|e| e.into_inner());
    (g.0.encap.clone(), g.0.secret().to_vec())
}

fn new_letter_state() -> LetterState {
    std::sync::Mutex::new((crate::letter::LetterIdentity::generate(), crate::letter::LetterRelay::new()))
}

/// TEST BUILDS ONLY — each simulated PROCESS's own Letter state (the twin of `persist::set_thread_node_files_for_test`):
/// a daemon is one process = one ring, but the journey simulator runs several nodes in one test process, where the one
/// static was SHARED — a letter admitted on node 0 sat in node 2's ring with no wire leg, whichever producer drained
/// `letter_pending_cms` first sealed it, and the identity's ML-KEM keygen ran on whichever node thread touched it first.
/// MEASURED (lane b 2026-10-24, replay-r8.log): that first touch moved node 1's seeded entropy stream on one run and not
/// the other, so one seed ran to two chains. Keyed by the simulated datadir; a boot ([`letter_new_process_for_test`])
/// starts a new process's empty ring, as a restart does. O1-FOOTPRINT-REVIEWED: test scaffold, one leaked slot per
/// simulated process boot.
#[cfg(test)]
fn letter_state_of_simulated_process(dir: std::path::PathBuf) -> &'static LetterState {
    let mut map = LETTER_PER_PROCESS_FOR_TEST.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    map.entry(dir).or_insert_with(|| Box::leak(Box::new(new_letter_state())))
}

#[cfg(test)]
static LETTER_PER_PROCESS_FOR_TEST: std::sync::Mutex<std::collections::BTreeMap<std::path::PathBuf, &'static LetterState>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// TEST BUILDS ONLY — the simulated process whose datadir this thread names boots: its Letter state is a new process's.
#[cfg(test)]
pub(crate) fn letter_new_process_for_test() {
    if let Some(dir) = crate::persist::thread_node_dir_for_test() {
        LETTER_PER_PROCESS_FOR_TEST.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&dir);
    }
}

/// ⭐ Admit a gossiped/relayed sealed letter blob into the shared metadata-blind ring, CONTENT-DEDUPED.
/// Returns `true` iff NEW — the mesh handler re-gossips only new blobs (bounded flood). Shared by the
/// `/letter/send` RPC and the `WireMsg::Letter` gossip handler so a letter reaches its recipient on ANY node
/// and the recipient's wallet reads it from THIS node's `/letter/inbox`.
pub(crate) fn letter_relay_admit(blob: Vec<u8>) -> bool {
    let mut g = match letter_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(), // recover a poisoned lock; the ring is just opaque blobs
    };
    g.1.admit(blob)
}

/// The REAL letter commitments this node holds that still await a block ([`crate::letter::LetterRelay::
/// drain_pending_cms`]) — what the producer seals into [`crate::block::Block::letter_set`]'s front slots.
pub(crate) fn letter_pending_cms() -> Vec<[u8; 32]> {
    let g = match letter_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    g.1.drain_pending_cms()
}

/// Retire every pending commitment an ACCEPTED block's carried `letter_set` anchored — produce and ingest
/// both route here, so two producers never double-carry a letter and an echo is a no-op.
pub(crate) fn letter_mark_carried(letter_set: &[u8]) {
    let mut g = match letter_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    g.1.mark_carried(letter_set)
}

/// The still-fresh ring slice for a [`crate::protocol::WireMsg::LetterReq`] pull answer (non-consuming).
pub(crate) fn letter_fresh_blobs() -> Vec<Vec<u8>> {
    let g = match letter_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    g.1.fresh_blobs()
}

/// ⭐ One relay tick's EPIDEMIC RE-FLOOD batch ([`crate::letter::LetterRelay::flood_batch`]) — every blob still
/// in its freshness window, each queued to peers again by the serve loop. Retries deliver through Tor writer
/// stalls (the one-shot admit-flood measurably lost a wallet send on 2026-08-23); receiver dedup makes repeats free.
pub(crate) fn letter_flood_batch() -> Vec<Vec<u8>> {
    let mut g = match letter_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    g.1.flood_batch()
}

/// The sealed blob committed to by `cm`, if this node's ring currently holds it — the by-commitment fetch a
/// backfill answer and the record-lane writer read.
pub(crate) fn letter_blob_of(cm: &[u8; 32]) -> Option<Vec<u8>> {
    let g = match letter_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    g.1.blob_of(cm)
}

/// Process-wide faucet minter (crate::faucet) — TESTNET-ONLY. No held pool and nothing to fund: each request
/// seals a fresh confidential note for exactly what it dispenses, recorded on the ordinary note path. A tool-owned
/// demo recipient lets the node scan what it issued and prove arrival. Creation is gated on testnet, never mainnet.
static FAUCET: std::sync::OnceLock<Option<std::sync::Mutex<crate::faucet::Faucet>>> =
    std::sync::OnceLock::new();
/// `None` when the OS CSPRNG refused the demo key at first use: every faucet route then answers [`faucet_off`].
fn faucet_state() -> Option<&'static std::sync::Mutex<crate::faucet::Faucet>> {
    FAUCET.get_or_init(|| crate::faucet::Faucet::new().map(std::sync::Mutex::new)).as_ref()
}
/// The faucet's refusal when its demo key could not be drawn (503: the node is up, this tool is not).
fn faucet_off() -> (u16, String) {
    (
        503,
        "{\"status\":\"REFUSED\",\"reason\":\"NO_OS_RANDOMNESS\",\"detail\":\"the OS CSPRNG refused the faucet's demo key; the faucet is off on this node\"}"
            .to_string(),
    )
}
/// The faucet dev tool is TESTNET-ONLY and FAIL-CLOSED, gated on the node's OWN GENESIS — the authoritative
/// per-network chain identity (`ChainParams::genesis_parity_commit`, set to `network_genesis_prefix(net)` at genesis
/// and carried through every datadir resume). The faucet dispenses ONLY when that genesis equals the TESTNET prefix;
/// a mainnet chain (or any other) refuses it, so value-bearing mainnet coins can NEVER be printed — and this holds
/// no matter HOW the node was launched (there is no env to set and no way to fool it from outside the actual chain).
fn node_network_is_testnet<T: CellTransport>(rt: &Arc<Mutex<NodeRuntime<T>>>) -> bool {
    let g = rt.lock().unwrap_or_else(|e| e.into_inner());
    let genesis = &g.node().params().genesis_parity_commit;
    // A-F111: the rig network is a value-less local network like the testnet; mainnet (and every unknown name) still refuses
    *genesis == crate::params::network_genesis_prefix("testnet") || *genesis == crate::params::network_genesis_prefix("rig")
}

fn write_response(s: &mut TcpStream, code: u16, json: &str, cors: Option<&str>) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Bad Request",
    };
    // ⛔ DB-374: CORS echoes the ADMITTED origin (the wallet's webview, the node's own apps), never `*`. The old `*`
    // rested on "read-only chain data carries zero secret" — but this port also answers the node's own Letter inbox,
    // identity, peers and diagnostics, and with `*` any web page the user visited could read them.
    let out = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{json}",
        json.len(),
        crate::local_origin::cors_headers(cors)
    );
    s.write_all(out.as_bytes())?;
    s.flush()
}

/// Every `AssetSpendOutcome::Pending` answer: an otherwise-valid object whose spent note's record is not folded on this node
/// yet — a race the fold resolves (`MemberVerdict::Pending`), 409 + the retry code, never a wrong submission's 422.
fn asset_pending_answer() -> (u16, String) {
    (
        409,
        format!(
            "{{\"status\":\"ERROR\",\"error\":\"MEMBERSHIP_NOT_FOLDED_YET\",\"detail\":\"{}\"}}",
            crate::asset_tx::ASSET_SPEND_PENDING
        ),
    )
}

/// The most rows one directory read answers with (spec §12.6: a collection's pieces, the collections list). The size of
/// ONE ANSWER, derived from what a screen shows at once (a grid of 48 fills a desktop page twice over); a reader that
/// wants more asks for the next index range, so nothing is ever out of reach.
const DIR_READ_PAGE_MAX: usize = 48;

/// How many rows a directory read answers with: what the caller asked for, at least one, at most [`DIR_READ_PAGE_MAX`].
fn dir_read_page_len(asked: Option<u64>) -> usize {
    asked.and_then(|n| usize::try_from(n).ok()).unwrap_or(DIR_READ_PAGE_MAX).clamp(1, DIR_READ_PAGE_MAX)
}

/// IonSwap pools — one pool's row as JSON. Amounts are decimal strings (they are 128-bit); `prices` is the row's own ring
/// (`[seconds, price × 10^12]`), given whole for one pool and as its newest entry alone in a list.
/// One pool's row as the pools routes answer it. `now_week`: the lock week of this node's chain clock, what the lock status
/// is read at (spec §14.3); `supply`: the asset's whole supply as the chain recorded it, if it has.
/// DIGITAL-CASH-PRIVACY-REVIEWED: every figure is the pool's own public row (balances, shares, the lock table by date)
/// and the asset's public supply; no holder, wallet, note or order owner is named.
fn ion_row_json(r: &crate::ion_pool_tx::IonRow, symbol: &str, name: &str, whole_ring: bool, now_week: u32, supply: Option<u64>) -> String {
    use crate::ion_pool_tx::{lock_week_start_secs, IonState};
    let (kind, x, y, shares, locked, virtual_base) = match r.state {
        IonState::Curve(c) => ("curve", c.x, c.real, 0u128, 0u128, c.v),
        IonState::Pool(p) => ("pool", p.x, p.y, p.shares, p.locked, 0u128),
    };
    // ⭐ THE FEE A TRADE OF THIS POOL PAYS, from the constant the chain's own batch rule charges (`ion_pool::POOL_FEE` or
    // `CURVE_FEE` by the row's kind), so no page states a rate the chain does not report (pin
    // `no_page_states_a_fee_rate_the_chain_does_not_report`; MEASURED 2026-11-13: IonSwap's pools page wrote all four parts
    // of both splits as literals).
    let fee = match r.state {
        IonState::Curve(_) => crate::ion_pool::CURVE_FEE,
        IonState::Pool(_) => crate::ion_pool::POOL_FEE,
    };
    let ring: Vec<String> = r.prices.iter().skip(if whole_ring { 0 } else { r.prices.len().saturating_sub(1) }).map(|(t, p)| format!("[{t},{p}]")).collect();
    // ⭐ THE LIQUIDITY LOCK, as a page draws it: green (locked) when more than half of the pool cannot be taken out NOW
    // (shares locked until a later Monday, plus the shares no provider holds); orange (unlocked) otherwise. The exact
    // part and the first unlock date always ride beside it, so a dust lock never reads as a locked pool.
    let (fixed, of) = r.unremovable_now(now_week);
    let pct_e2 = if of == 0 { 0 } else { fixed.saturating_mul(10_000) / of };
    let status = if of > 0 && fixed.saturating_mul(2) > of { "locked" } else { "unlocked" };
    let first_unlock = r.locks.iter().find(|(w, _)| *w > now_week).map_or_else(|| "null".to_string(), |(w, _)| lock_week_start_secs(*w).to_string());
    let locks: Vec<String> = if whole_ring {
        r.locks.iter().map(|(w, n)| format!("{{\"week\":{w},\"unlock_secs\":{},\"shares\":\"{n}\",\"passed\":{}}}", lock_week_start_secs(*w), *w <= now_week)).collect()
    } else {
        Vec::new()
    };
    format!(
        "{{\"token\":\"{}\",\"symbol\":\"{}\",\"name\":\"{}\",\"kind\":\"{kind}\",\"token_atomic\":\"{x}\",\"usdm_atomic\":\"{y}\",\"shares\":\"{shares}\",\"locked_shares\":\"{locked}\",\"virtual_usdm_atomic\":\"{virtual_base}\",\"liquidity_usdm_atomic\":\"{}\",\"price_e12\":{},\"batch\":{},\"settled_through\":{},\"creator_owed_token_atomic\":\"{}\",\"creator_owed_usdm_atomic\":\"{}\",\"burned_token_atomic\":\"{}\",\"supply\":{},\"lock\":{{\"status\":\"{status}\",\"fixed_shares\":\"{fixed}\",\"of_shares\":\"{of}\",\"pct_e2\":{pct_e2},\"first_unlock_secs\":{first_unlock},\"now_week\":{now_week},\"now_secs\":{}}},\"locks\":[{}],\"prices\":[{}],\"fee\":{{\"pool_bps\":{},\"creator_bps\":{},\"protocol_bps\":{},\"publisher_bps\":{},\"total_bps\":{}}}}}",
        hex_encode(&r.token),
        json_escape(symbol),
        json_escape(name),
        r.liquidity_usdm(),
        r.price().map_or_else(|| "null".to_string(), |p| p.to_string()),
        r.batch,
        r.settled_through,
        r.owed_creator_x,
        r.owed_creator_y,
        r.burned_x,
        supply.map_or_else(|| "null".to_string(), |v| format!("\"{v}\"")),
        lock_week_start_secs(now_week),
        locks.join(","),
        ring.join(","),
        fee.pool_bps,
        fee.creator_bps,
        fee.protocol_bps,
        fee.publisher_bps,
        fee.total_bps()
    )
}

/// IonSwap's fee schedule as the chain charges it (`ion_pool::POOL_FEE` and `CURVE_FEE`, the constants the batch rule reads),
/// beside every pool read, so a page can show what a trade of a pool, or of a launch curve not yet made, pays without stating a
/// rate the chain does not report.
fn ion_fees_json() -> String {
    let one = |f: crate::ion_pool::FeeSplit| {
        format!(
            "{{\"pool_bps\":{},\"creator_bps\":{},\"protocol_bps\":{},\"publisher_bps\":{},\"total_bps\":{}}}",
            f.pool_bps,
            f.creator_bps,
            f.protocol_bps,
            f.publisher_bps,
            f.total_bps()
        )
    };
    format!("\"fees\":{{\"pool\":{},\"curve\":{}}}", one(crate::ion_pool::POOL_FEE), one(crate::ion_pool::CURVE_FEE))
}

#[cfg(test)]
mod ion_fee_route_tests {
    /// ⛔ THE POOL ROUTES REPORT THE FEE THE CHAIN CHARGES, part by part, so a page states no rate of its own (MEASURED
    /// 2026-11-13: IonSwap's pools page wrote both splits as literals; `no_page_states_a_fee_rate_the_chain_does_not_report`).
    /// TWO-PARTY-REVIEWED: the second party is the page that reads these fields through the wallet (`lib/pools.js` feeOf);
    /// this pin holds the node's half, that every part the batch rule charges is the part the route reports.
    #[test]
    fn the_pool_routes_report_the_fee_split_the_batch_rule_charges() {
        let v: serde_json::Value = serde_json::from_str(&format!("{{{}}}", super::ion_fees_json())).expect("the schedule is JSON");
        for (kind, f) in [("pool", crate::ion_pool::POOL_FEE), ("curve", crate::ion_pool::CURVE_FEE)] {
            let g = &v["fees"][kind];
            for (field, want) in [
                ("pool_bps", f.pool_bps),
                ("creator_bps", f.creator_bps),
                ("protocol_bps", f.protocol_bps),
                ("publisher_bps", f.publisher_bps),
                ("total_bps", f.total_bps()),
            ] {
                assert_eq!(g[field].as_u64().map(u128::from), Some(want), "⛔ the {kind} schedule's {field} is not the chain's");
            }
        }
    }
}

fn err_json(code: &str) -> String {
    format!("{{\"status\":\"REJECTED\",\"reason\":\"{}\"}}", code)
}

// ── OLI locator index: the served build, keyed on the served-record frontier ──

/// The frontier the served index is keyed on: EVERY served record (`oli::served_index_frontier`). A new record keys a new build,
/// run off the lock by one builder at a time while the held index keeps serving, so a note is findable from the build after
/// its record lands — never a full epoch later, which is what the 64-block floor this replaces did (and the wallet has no tail
/// walk to cover it).
fn oli_index_frontier(blocks: u64) -> u64 {
    crate::oli::served_index_frontier(blocks) // every served record, never the last epoch boundary (oli::served_index_frontier)
}

/// The current epoch's index, built once per epoch and shared by every request. Serving-tier state: it
/// is derived data, never consensus, and a node that never serves a restore never builds it.
/// DB-107 (run 102l, 2026-09-19): THE INDEX IS BUILT OFF THE RUNTIME LOCK AND OFF THE REQUEST THREAD. The
/// build used to run inside the handler with `rt` held — a stuck build (the per-key overflow loop, oli.rs)
/// froze every RPC and the tick for minutes on three consecutive runs. Now the handler snapshots the
/// build's inputs (the klog, the chain key, the seed — a few KB, under the lock for microseconds), spawns
/// ONE builder thread per epoch, and serves the previous epoch's index while it runs; the first request of a
/// fresh process gets `None` (the wallet's OLI lane bails to its other doors and re-asks). A stale epoch is a
/// valid index — the locator answers for every note it holds, and the newest blocks arrive next epoch.
///
/// ⛔ DB-332: the cache is the NODE's (`Node::oli_serve_cache`), never the process's. It was a `static` keyed only by
/// the epoch end, so every runtime in one process was served whichever node built first.
fn oli_index<T: CellTransport>(rt: &NodeRuntime<T>) -> Option<Arc<crate::oli::Index>> {
    let cell = rt.node().oli_serve_cache();
    // ⭐ THE EPOCH FLOOR IS THE SERVER-SIDE PREPROCESSING, NOT A WINDOW — RESTORED.
    //
    // user 2026-08-10: *"didnt we solve the oli already with 0 walk? Why isnt the wallet using our fixed oli
    // with no walk?"* The wallet IS: detection is address-carried PRF locators + LWE PIR, measured at 17ms
    // cold restore with no wallet-side scan. `[[project_oli_locator_pir_cold_restore]]` states the design
    // explicitly: OLI *relocates* the unavoidable linear pass onto the UNTRUSTED SERVING NODE, where it is
    // shardable and off the wallet's critical path — it does not eliminate it, because private retrieval of
    // one record out of N from a single server is Ω(N) server compute per UN-PREPROCESSED query.
    //
    // This epoch key IS that preprocessing. I removed it reading it as a banned reachability window; it is
    // not — nothing is refused for age by it. Removing it made the cache key change every block, so the
    // server's linear pass ran per query instead of once per epoch. MEASURED: a restore at 73,240ms and
    // rising with chain length — the growth the user then correctly called out. Restored.
    //
    // The real defect I was chasing (a note in the newest 0..63 blocks being unindexed) is NOT fixed by
    // deleting the preprocessing. It is fixed by serving the epoch index PLUS the un-indexed tail, which is
    // the next brick and does not disturb this amortisation.
    // ⛔⛔⛔ THE EPOCH FLOOR MADE EVERY FRESH NOTE UNFINDABLE. Serve the epoch index PLUS the TAIL.
    //
    // The comment above already named this as the outstanding brick ("serving the epoch index PLUS the
    // un-indexed tail"), and it is the reason a payment can never be located: `oli_epoch_end` truncates the
    // build to the last epoch boundary, so any note recorded AFTER that boundary is in no served index. A
    // freshly credited note is ALWAYS in that tail. It is not a rare edge — it is every new payment.
    //
    // MEASURED across two fresh chains, with every other layer proven correct:
    //   node:   [faucet]    clue attached form=v2 key=4abc6447
    //   wallet: [oli-ask]   domain=recv first_key=4abc6447 shard=9   (shard_bits=5, 0x4a>>3 == 9 ✓)
    //   node:   [oli-build] indexed 1 tag(s), 0 unplaced
    //   wallet: [oli-yield] locate returned 0 position(s)
    // and `an_entry_written_by_build_shard_is_read_back_at_the_coordinates_query_coords_names` proves the
    // write/read coordinates agree. Every layer was right; the note simply was not in the table.
    //
    // COVER THE WHOLE ADDRESS SPACE. `da_top` is the address frontier, so building to it includes the tail
    // and a note is findable the moment it is recorded — findability by construction, which is the property
    // that matters: a note its owner cannot locate is a note they cannot spend.
    //
    // The cache still amortises: it is keyed on the address frontier, so repeated queries between records
    // share one build, and only a NEW record triggers a rebuild. Sizing the tail work down to O(epoch) by
    // keeping a second, small tail index is the follow-on optimisation — it changes the cost, never the
    // answer, and is not required for a note to be found.
    // ⛔⛔⛔ REVERTED — `da_address_top()` IS AN ADDRESS, NOT A COUNT, AND IT CRASHED THE NODE.
    //
    // I passed the DA address frontier here to cover the un-indexed tail. Record addresses are derived from
    // block ids (`first8(id) & 0x00ff..` * 4), so `da_top` is ~10^17, not a small ordinal. The builder sized
    // itself over that range and the node died outright:
    //   MEASURED 2026-08-10: `memory allocation of 6906291932120222808 bytes failed` — 6.9 EXABYTES —
    //   with `:27860 DOWN` and `[oli-build] indexed 0 tag(s)` on the way out.
    //
    // The tail defect above is REAL and still open: `oli_epoch_end` truncates to the last epoch boundary, so
    // a freshly credited note is in no served index and `locate` returns 0 every time. But the fix is to
    // iterate the KLOG (which is keyed by the tags actually written) past the epoch floor — NOT to widen an
    // address-space bound, which is not a count of anything.
    let build_to = oli_index_frontier(rt.node().served_block_count());
    let mut g = cell.state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((cached_to, idx)) = g.built.as_ref() {
        if *cached_to == build_to {
            return Some(Arc::clone(idx));
        }
    }
    // ONE builder at a time: the frontier moves with every new record, so a build already running is never doubled — the
    // held index keeps serving and the next request after it lands starts the build for the newer frontier.
    if g.building.is_none() {
        g.building = Some(build_to);
        let inputs = rt.node().oli_build_inputs(build_to);
        let cell2 = Arc::clone(&cell);
        let spawned = std::thread::Builder::new()
            .name("oli-index-build".into())
            .spawn(move || {
                // ⭐ DB-408: however this build ends — it lands, or the thread unwinds — `building` is released and every
                // reader waiting in `oli_index_ready` is woken, so no waiter outlives its builder.
                // ROOT-LAYER: the builder is the one producer of the served index, so it is the one place that can say
                // "this build is over"; a reader cannot know it.
                // MEASURED: before → a builder that unwound left `building` set forever (no rebuild of that epoch, READ);
                // after → `db408_…` (the release is what wakes the waiter in that pin).
                // MUST-STAY-GREEN: db332 (each node its own index); the OLI route pins.
                struct Release(Arc<crate::node::OliServeCell>, u64);
                impl Drop for Release {
                    fn drop(&mut self) {
                        let mut g = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
                        if g.building == Some(self.1) {
                            g.building = None;
                        }
                        drop(g);
                        self.0.landed.notify_all();
                    }
                }
                let _release = Release(Arc::clone(&cell2), build_to);
                let t0 = std::time::Instant::now();
                let built = Arc::new(crate::oli::Index::build(
                    &inputs.klog,
                    &inputs.chain_key,
                    0,
                    inputs.end_seq,
                    1,
                    inputs.epoch_seed,
                ));
                eprintln!(
                    "[oli-build] epoch {} index built off-lock in {} ms ({} tag(s))",
                    build_to,
                    t0.elapsed().as_millis(),
                    inputs.klog.len()
                );
                let mut g = cell2.state.lock().unwrap_or_else(|e| e.into_inner());
                // An older epoch's build that lands after a newer one never replaces it.
                if g.built.as_ref().map_or(true, |(held_to, _)| *held_to <= build_to) {
                    g.built = Some((build_to, built));
                }
            });
        if spawned.is_err() {
            // No builder exists, so nobody may wait on one: the next ask starts it again.
            g.building = None;
        }
    }
    g.built.as_ref().map(|(_, idx)| Arc::clone(idx))
}

/// ⭐ DB-408 — THE ONE READ OF THE SERVE INDEX FOR A REQUEST (`/oli_params`, `/oli_hint`, `/oli_table`, `/oli_answer`):
/// [`oli_index`] — the held epoch index, a stale epoch's while the next builds (DB-107) — and, on a node that holds NO
/// index yet, the build that call just started, awaited OFF the runtime lock. Also the served block count, read under
/// the same lock.
///
/// MEASURED sim-20261007-020907 (T3): every node restart empties the cache (it is serving-tier state), so the first ask
/// after a restart was answered 503 `BUILDING … ask again` while the build it had started took 0 ms (`[oli-build] epoch
/// 512 index built off-lock in 0 ms`, every build that run). The wallet's change-index sweep reads that as "the chain
/// cannot be asked" and refuses the send (the T3 unbond), and detection reads it as zero notes (`[oli-bail]`). Bitcoin
/// Core answers a request that arrives during its warm-up when the warm-up ends (`-rpcwait`); here the server does the
/// waiting, so no client needs a retry loop for a state that lasts one build.
/// ROOT-LAYER: the 503 was PRODUCED here — the serve path answered before the build it had itself started could land;
/// the four routes are its only readers, and all four read through this one function.
/// MEASURED: before → T3 unbond refused "/oli_params: status code 503" (sim-20261007-020907); after → `db408_…` asks a
/// node with an empty cache over the production router and is answered 200 on the FIRST ask.
/// MUST-STAY-GREEN: db332 (each node serves its own index); the late-clue and DB-228 table pins; the wallet's OLI pins.
///
/// The wait never holds the runtime lock (DB-107: a stuck build under that lock froze every RPC and the tick) and never
/// outlives its builder (`OliServeCell::landed` is raised however the build ends). The HTTP server runs one thread per
/// connection, so a waiting reader stalls only its own connection. A builder that ends without an index (it unwound)
/// leaves `None`, answered 503 as before, and the next ask starts a new build.
/// cons: a request reaching a node with no index yet waits one build (0 ms at the simulator's chain, MEASURED above) on
/// its own connection thread instead of returning at once; nothing on any other path.
fn oli_index_ready<T: CellTransport>(rt: &Arc<Mutex<NodeRuntime<T>>>) -> (Option<Arc<crate::oli::Index>>, u64) {
    // ⭐ READERS NEVER QUEUE BEHIND THE WRITER (lane stable 2026-11-01, performance pillar). Every OLI route took the RUNTIME
    // lock only to read the cache handle and the served block count, so a wallet's balance refresh waited out the node's
    // tick. MEASURED: 1,518 of 1,594 samples of a restoring wallet's `oli_quick_restore` (stable/wsample/60933.txt) sat
    // reading the reply while the node's RPC thread waited at this lock (stable/relay4.sample.txt: `oli_index_ready` → `Mutex::lock`
    // → `__psynch_mutexwait`, 73–101 samples per RPC thread). The cell is this node's own (taken once, under the lock, and
    // kept by the runtime's address — one entry per runtime of the process); its runtime publishes the served epoch every
    // relay tick. When the built index is that epoch's, it is answered here; any other state (no index, an epoch roll, a
    // build to start) takes the locked path below, unchanged. Serving-tier data only — the same bytes either way.
    static CELLS: Mutex<Vec<(usize, std::sync::Weak<crate::node::OliServeCell>)>> = Mutex::new(Vec::new());
    let key = Arc::as_ptr(rt) as usize;
    let known = CELLS.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(k, _)| *k == key).and_then(|(_, w)| w.upgrade());
    if let Some(cell) = known {
        let to = cell.published_to.load(std::sync::atomic::Ordering::Acquire);
        if to != u64::MAX {
            let g = cell.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((built_to, idx)) = g.built.as_ref() {
                if *built_to == to {
                    return (Some(Arc::clone(idx)), to);
                }
            }
        }
    }
    let (held, cell, blocks) = {
        let g = rt.lock().unwrap_or_else(|e| e.into_inner());
        (oli_index(&g), g.node().oli_serve_cache(), g.node().served_block_count())
    }; // ← the rt guard drops here: the wait below never holds the runtime lock
    {
        let mut cells = CELLS.lock().unwrap_or_else(|e| e.into_inner());
        cells.retain(|(_, w)| w.strong_count() > 0);
        if !cells.iter().any(|(k, _)| *k == key) {
            cells.push((key, Arc::downgrade(&cell)));
        }
    }
    if held.is_some() {
        return (held, blocks);
    }
    let mut g = cell.state.lock().unwrap_or_else(|e| e.into_inner());
    while g.built.is_none() && g.building.is_some() {
        g = cell.landed.wait(g).unwrap_or_else(|e| e.into_inner());
    }
    (g.built.as_ref().map(|(_, idx)| Arc::clone(idx)), blocks)
}

// ── tiny helpers (no serde/hex crate) ──

/// Extract a JSON string field value: finds `"field"` then the next `"..."` after the following `:`.
/// Sufficient for the fixed-shape `{"tx_as_hex":"…",…}` body; not a general parser.
/// Last successful full `/get_info` body — served verbatim when the rt lock is contended, so a status
/// probe ALWAYS answers (proof-of-life never queues behind adopt/heal work). One representation: only the
/// real serializer ever writes it.
/// ⭐⭐⭐ THE LIVENESS SNAPSHOT — the few fields a status probe needs, PUBLISHED OUTSIDE THE RUNTIME LOCK.
///
/// ⛔⛔⛔ MEASURED, AND IT IS THE USER'S FIRST IMPRESSION OF THE CHAIN. A freshly launched node on a quiet
/// machine, polled every 3 s from t=0 (scratchpad `probe.out`):
///
/// ```text
/// [boot-timeline] handing off to RPC serve (bind) at 1ms
/// t=3s  … t=100s   {"status":"OK","busy":true}      <- no height, for 103 SECONDS
/// t=103s           …,"height":180,…                 <- first usable answer
/// ```
///
/// The node was mining the whole time. What failed was the READER: `/get_info` takes `try_lock`, loses it
/// to the drain, and falls back to a cache that is only warmed by whoever wins the lock — so while the
/// lock is busy the cache stays cold and the answer stays empty. `busy:true` describes the READER'S
/// problem and says nothing about the node, which is exactly the wallet's *"Starting your node…"* hanging
/// on a node that is running perfectly, and the `node1 never served RPC` the ecosystem gate reported
/// twice against a node that had bound in 1 ms and produced 167 blocks.
///
/// PERFORMANCE PILLAR (user 2026-09-23): *"readers never queue behind the writer"*, and *"errors are
/// performance: fail CLOSED and LEGIBLY, naming the real state"*. A probe that cannot be answered in 1 ms
/// from values the node already has is not a lock problem, it is a publishing problem.
///
/// So the runtime PUBLISHES these as it ticks — it already holds the lock there, the write is three
/// atomic stores, and a reader takes them with no lock at all. This does not fix whatever holds the lock
/// for seconds (that is measured separately); it makes the node able to answer regardless.
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: chain height, block count and a mesh flag — the same public
/// chain-progress figures `/get_info` already serves to everyone. No note, amount, key, owner or count of
/// anything private.
pub static LIVE_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static LIVE_BLOCKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static LIVE_MESH_JOINED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set once the runtime has published at least one tick — before that the node genuinely has nothing to
/// report and says so, rather than reporting a zero that looks like a stalled chain.
pub static LIVE_PUBLISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// ⛔⛔⛔ THE WEDGE HAS TO RIDE THE LOCK-FREE PATH TOO. A node whose fold is stuck is exactly the node
/// whose lock is held (its drain spends the whole tick budget going nowhere), so the busy answer is the
/// one a reader is MOST likely to get from it — and without this the busy answer carries a perfectly
/// current `height` and says nothing at all about the fold. That is precisely the state the live pair was
/// in for ~2.5 days on 2026-09-24.
pub static LIVE_FOLD_UNFOLDED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static LIVE_FOLD_WEDGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Publish the liveness snapshot. Called by the runtime tick, which already holds the lock.
pub fn publish_live_status(
    height: u64,
    blocks: u64,
    mesh_joined: bool,
    fold_unfolded: u64,
    fold_wedged: bool,
) {
    use std::sync::atomic::Ordering::Relaxed;
    LIVE_HEIGHT.store(height, Relaxed);
    LIVE_BLOCKS.store(blocks, Relaxed);
    LIVE_MESH_JOINED.store(mesh_joined, Relaxed);
    LIVE_FOLD_UNFOLDED.store(fold_unfolded, Relaxed);
    LIVE_FOLD_WEDGED.store(fold_wedged, Relaxed);
    LIVE_PUBLISHED.store(true, Relaxed);
}

/// CONFIDENTIAL SOLVENCY (digital-cash pillar): value-hiding Poseidon commitments to the reserve + the circulating
/// liability + the proven backing ratio — NEVER an amount / supply / count. An observer learns the reserve backs the
/// liability at `ratio_bps`, never how much. `backed` holds BY CONSTRUCTION: every confidential mint required a
/// `reserve_commit >= ratio * liability_commit` ZK proof, and a peg-out that would break the invariant is unprovable →
/// rejected. Mirrors the `SolvencyProof` carrier's opaque commitment-only IO. ONE serializer for `/get_solvency`,
/// whether the runtime published the answer or a cold process read it under the lock.
pub fn solvency_body(
    rc: crate::spend_frontier::Digest4,
    mc: crate::spend_frontier::Digest4,
    ratio: u32,
) -> String {
    let hex4 = |l: crate::spend_frontier::Digest4| {
        let mut s = String::new();
        for x in l {
            s.push_str(&format!("{x:016x}"));
        }
        s
    };
    format!(
        "{{\"status\":\"OK\",\"model\":\"confidential-solvency\",\"backed\":true,\"ratio_bps\":{ratio},\"reserve_commit\":\"{}\",\"liability_commit\":\"{}\"}}",
        hex4(rc),
        hex4(mc)
    )
}

/// ⛔ THE PUBLISHED SOLVENCY ANSWER: written by the runtime once per tick, while it already holds the lock, and read
/// by `/get_solvency` without touching that lock.
/// ROOT-LAYER: the value is PRODUCED by the writer that holds the peg ledger, at the moment it holds it (the tick's
/// publish point, beside `publish_live_status`). Reading it there means no reader ever waits on a block apply.
/// MEASURED: ecosystem gate 2026-09-28 20:28, step 7: `/api/reserves` answered 503. The sovereign loopback's 1.5 s
/// read timed out while one block apply held the runtime lock 1.2-1.3 s; the same surface passed 9/9 at 20:09.
/// MUST-STAY-GREEN: the solvency body is byte-identical (one serializer, `solvency_body`); every step-7 launchpad
/// surface; `/get_info`'s DB-137 path is untouched. A poisoned mutex still holds a complete string (it is replaced
/// whole under the lock), so reading through the poison serves a real published answer, never a partial one.
static LIVE_SOLVENCY: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// Publish the solvency answer (see [`LIVE_SOLVENCY`]): one short string per tick, commitments only.
pub fn publish_live_solvency(
    rc: crate::spend_frontier::Digest4,
    mc: crate::spend_frontier::Digest4,
    ratio: u32,
) {
    let body = solvency_body(rc, mc, ratio);
    match LIVE_SOLVENCY.lock() {
        Ok(mut g) => *g = body,
        Err(p) => *p.into_inner() = body,
    }
}

/// The last published solvency answer, or `None` before the runtime's first tick (then `/get_solvency` reads it
/// under the lock, once).
fn published_solvency() -> Option<String> {
    let g = match LIVE_SOLVENCY.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if g.is_empty() {
        None
    } else {
        Some(g.clone())
    }
}

/// The busy answer, made HONEST: it carries the height the node actually holds.
fn busy_info_json() -> String {
    use std::sync::atomic::Ordering::Relaxed;
    if !LIVE_PUBLISHED.load(Relaxed) {
        // Nothing published yet — the runtime has not completed a tick. Say that, do not invent a zero.
        return "{\"status\":\"OK\",\"busy\":true,\"warming\":true}".to_string();
    }
    format!(
        "{{\"status\":\"OK\",\"busy\":true,\"height\":{},\"blocks\":{},\"blue_score\":{},\"mesh_joined\":{},\"fold_unfolded\":{},\"fold_wedged\":{}}}",
        LIVE_HEIGHT.load(Relaxed),
        LIVE_BLOCKS.load(Relaxed),
        LIVE_HEIGHT.load(Relaxed),
        LIVE_MESH_JOINED.load(Relaxed),
        LIVE_FOLD_UNFOLDED.load(Relaxed),
        LIVE_FOLD_WEDGED.load(Relaxed),
    )
}

fn get_info_cache() -> &'static std::sync::Mutex<String> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(String::new()))
}

/// ⛔ DB-137 (2026-09-21): THE INFO CACHE REFRESHED ONLY WHEN A REQUEST WON `try_lock`, AND ON A BUSY NODE IT
/// NEVER DID. The live joiner served `/get_info` height 788 for ten minutes; `/get_height` said 1,299 and its
/// log had finalized height 1,225: every request arrived with the runtime lock held, so every request was
/// answered from the stale string. The wallet's balance verdict and every operator reading judge a node by this
/// door. The producer side now refreshes it: the runtime start spawns one thread that, twice a second, takes
/// the runtime lock ONCE (a blocking wait that ends when the tick releases it) and then lets the ordinary route
/// build and store the string. Two calls per second, no state, no growth; the request path is unchanged and
/// keeps serving the cache whenever the lock is busy.
/// ROOT-LAYER: the runtime is the producer of every field in that string; the request path was the wrong side
/// to own its freshness.
/// MEASURED: joiner 28901 — `/get_info` h 788 against `/get_height` h 1,299 (17:41); after its restart the two
/// agreed only until the next long lock hold. Expected after: the two doors agree within one tick.
/// MUST-STAY-GREEN: `/get_info` still never blocks a request behind the runtime lock; the busy answer stays.
pub fn refresh_get_info_cache<T: CellTransport>(rt: &Arc<Mutex<NodeRuntime<T>>>) {
    // MEASURED 2026-09-21 18:43 (first version, "release the lock, then try_lock in the route"): the syncing
    // joiner's tick re-took the lock before the route could; its info sat at h 114 as `/get_height` reached
    // 183. The refresher therefore builds UNDER a lock it owns: this thread marks itself, and the route's
    // `/get_info` arm takes the lock blocking for a marked thread (a wait bounded by one tick) instead of
    // trying it. Request threads are never marked and keep the try-lock-or-cache behaviour.
    INFO_REFRESH_BLOCKING.with(|f| f.set(true));
    let _ = route(rt, "GET", "/get_info", "");
    INFO_REFRESH_BLOCKING.with(|f| f.set(false));
}

thread_local! {
    /// True only on the info-refresh thread for the duration of its own `/get_info` build (DB-137).
    static INFO_REFRESH_BLOCKING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// ⛔ DB-405 — the `(version, digest)` a PIR answer ask echoes from its hint (both window-index answer doors): the table
/// version the hint covered and that table's `window_index::table_digest`. A refusal names the missing field.
fn versioned_ask(body: &str) -> Result<(u64, [u8; 32]), &'static str> {
    let version = json_num_field(body, "version").ok_or("BAD_REQUEST:VERSION")?;
    let digest = json_str_field(body, "digest_hex")
        .and_then(|h| hex_decode(&h))
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or("BAD_REQUEST:DIGEST")?;
    Ok((version, digest))
}

/// §BR-2 — a co-signed deposit's sweep authorization from a mint request: `depositor_x_hex`, `sweep_txid` (display hex),
/// `sweep_vout`, `sweep_value_sats`, `sweep_fee_sats`, `sweep_sig_hex`. `Ok(None)` when the request names no depositor
/// (a Monero or wrapped deposit); `Err` names the malformed field.
pub(crate) fn sweep_auth_from_json(body: &str) -> Result<Option<crate::peg_attest::SweepAuth>, &'static str> {
    let Some(d) = json_str_field(body, "depositor_x_hex") else { return Ok(None) };
    let depositor_x: [u8; 32] = hex_decode(&d).and_then(|b| b.try_into().ok()).ok_or("DEPOSITOR")?;
    let txid = json_str_field(body, "sweep_txid").and_then(|h| crate::btc_tx::txid_from_display_hex(&h)).ok_or("SWEEP_TXID")?;
    let vout = u32::try_from(json_num_field(body, "sweep_vout").ok_or("SWEEP_VOUT")?).map_err(|_| "SWEEP_VOUT")?;
    let value_sats = json_num_field(body, "sweep_value_sats").ok_or("SWEEP_VALUE")?;
    let fee_sats = json_num_field(body, "sweep_fee_sats").ok_or("SWEEP_FEE")?;
    let sig: [u8; 64] = json_str_field(body, "sweep_sig_hex").and_then(|h| hex_decode(&h)).and_then(|b| b.try_into().ok()).ok_or("SWEEP_SIG")?;
    Ok(Some(crate::peg_attest::SweepAuth { depositor_x, txid, vout, value_sats, fee_sats, sig }))
}

pub(crate) fn json_str_field(body: &str, field: &str) -> Option<String> {
    // REAL JSON decoding, not a scanner. The hand-rolled version consumed a backslash and pushed the next
    // char VERBATIM, so every `\uXXXX` escape decoded wrong (`` → the literal text `u001f`). A wallet
    // signs the true bytes, the node verified over the mangled ones, and the signature was refused — the
    // profile lane's topic carries `\u{1f}` and hit this on its FIRST live submit (measured 2026-08-24:
    // `[dir-submit] REFUSED — signature invalid`). serde_json gives the one canonical decode for the whole
    // class: \uXXXX, \n, \t, \\, \" and surrogate pairs, on every endpoint that reads a string field.
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(v.get(field)?.as_str()?.to_string())
}

/// Extract a JSON unsigned-integer field. Sufficient for `"pow_stamp":<n>` in the fixed-shape body.
/// Read a JSON boolean field. Used where a caller must NAME which coordinate space a number is in, rather
/// than the node inferring it from magnitude (a heuristic that reads as a height gate and drifts as the chain
/// grows).
pub(crate) fn json_bool_field(body: &str, field: &str) -> Option<bool> {
    let key = format!("\"{field}\"");
    let at = body.find(&key)?;
    let rest = &body[at + key.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn json_num_field(body: &str, field: &str) -> Option<u64> {
    let key = format!("\"{}\"", field);
    let after_key = &body[body.find(&key)? + key.len()..];
    let after_colon = &after_key[after_key.find(':')? + 1..];
    let digits: String = after_colon
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = hex_val(b[i])?;
        let lo = hex_val(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(all(test, feature = "pins-harness"))]
mod unspent_wire_tests {
    use super::*;

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::transport::LoopbackTransport;

    /// The faucet gate is FAIL-CLOSED: it dispenses ONLY on an explicit testnet network, and NEVER on mainnet or an
    /// unset/unknown one — so value-bearing mainnet coins can never be printed. It also matches the node's OWN genesis
    /// derivation (`params::net_id`): the exact same names are treated as testnet, so gate and chain never disagree.
    #[test]
    fn faucet_gate_is_fail_closed_and_never_mainnet() {
        use crate::params::network_genesis_prefix;
        // The faucet dispenses iff the node's genesis == the TESTNET prefix — EXACTLY the comparison
        // `node_network_is_testnet` performs on `params().genesis_parity_commit`. A testnet chain passes; mainnet,
        // unset, and unknown all resolve to the MAINNET genesis and REFUSE, so value-bearing mainnet coins can never
        // be printed regardless of how the node was launched (there is no env to set or spoof).
        let testnet = network_genesis_prefix("testnet");
        assert_eq!(
            network_genesis_prefix("test"),
            testnet,
            "test == testnet chain → faucet ON"
        );
        assert_eq!(
            network_genesis_prefix("regtest"),
            testnet,
            "regtest rides testnet → faucet ON"
        );
        assert_ne!(
            network_genesis_prefix("mainnet"),
            testnet,
            "a MAINNET node NEVER dispenses"
        );
        assert_ne!(
            network_genesis_prefix(""),
            testnet,
            "unset → mainnet genesis → faucet OFF (no mainnet coins)"
        );
        assert_ne!(
            network_genesis_prefix("main"),
            testnet,
            "unknown → mainnet genesis → faucet OFF"
        );
    }

    /// A runtime on the TESTNET genesis/params (the faucet route is testnet-gated), otherwise like `fresh`.
    /// ⭐ SATOSHI §8.2/§8.3 — the three reward doors fail CLOSED on malformed input before anything is read or written:
    /// `/submit_sat_bond` refuses an empty or partial body (400, parity with `/submit_asset_spend`); `/provision_reward_recipient`
    /// refuses a missing key (422), a spend key that is not 32 bytes (422, DB-395) and a locator key that is not 32 bytes (422) —
    /// all before the file half runs; and
    /// `GET /reward_recipient` names the test node's recipient (provisioned, a 1184-byte public key, counter 0) without ever
    /// answering the locator key.
    #[test]
    fn the_sat_reward_doors_refuse_malformed_input_and_the_recipient_read_never_answers_the_locator_key() {
        let rt = fresh_testnet();
        let (code, body) = route(&rt, "POST", "/submit_sat_bond", "{}");
        assert_eq!(code, 400, "{body}");
        assert!(body.contains("MALFORMED_SAT_BOND"), "{body}");
        let (code, body) = route(&rt, "POST", "/submit_sat_bond", "{\"note0\":\"00\",\"weight\":5}");
        assert_eq!(code, 400, "{body}");
        let (code, body) = route(&rt, "POST", "/provision_reward_recipient", "{}");
        assert_eq!(code, 422, "{body}");
        assert!(body.contains("PROVISION_NEEDS_SCAN_KEY_SPEND_KEY_AND_SAT_LOCATOR_KEY"), "{body}");
        // DB-395: every reward is sealed to the wallet's spend key, so the door names it, and refuses a malformed one first
        let (k32, k1) = ("00".repeat(32), "00");
        let (code, body) = route(
            &rt,
            "POST",
            "/provision_reward_recipient",
            &format!("{{\"scan_ek_hex\":\"0000\",\"spk_hex\":\"{k1}\",\"sat_loc_sk_hex\":\"{k32}\"}}"),
        );
        assert_eq!(code, 422, "{body}");
        assert!(body.contains("SPEND_KEY_IS_NOT_32_BYTES"), "{body}");
        let (code, body) = route(
            &rt,
            "POST",
            "/provision_reward_recipient",
            &format!("{{\"scan_ek_hex\":\"0000\",\"spk_hex\":\"{k32}\",\"sat_loc_sk_hex\":\"{k1}\"}}"),
        );
        assert_eq!(code, 422, "{body}");
        assert!(body.contains("SAT_LOCATOR_KEY_IS_NOT_32_BYTES"), "{body}");
        let (code, body) = route(&rt, "GET", "/reward_recipient", "");
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("\"provisioned\":true"), "a test node starts with its wallet's recipient: {body}");
        assert!(body.contains("\"next_index\":0"), "{body}");
        let ek_hex = json_str_field(&body, "scan_ek_hex").expect("the public scan key is answered");
        assert_eq!(ek_hex.len(), 2 * crate::satoshi::SCAN_EK_BYTES, "an ML-KEM-768 encapsulation key");
        assert!(!body.contains("loc"), "⛔ the recipient read answered more than the public key and the counter: {body}");
    }

    pub(super) fn fresh_testnet() -> Arc<Mutex<NodeRuntime<LoopbackTransport>>> {
        let node = crate::node::Node::with_params(
            crate::persist::real_v27_fixture_tests::testnet_genesis(),
            {
                let mut p = crate::persist::real_v27_fixture_tests::testnet_params();
                p.record_fold_depth = 0; // these tests' subject is not the fold delay: fold at the tip
                p
            },
        )
        .expect("testnet node");
        let (ta, _tb) = LoopbackTransport::pair();
        Arc::new(Mutex::new(NodeRuntime::new(node, ta)))
    }

    pub(super) fn fresh() -> Arc<Mutex<NodeRuntime<LoopbackTransport>>> {
        // `Node::new_folding_at_tip_for_test`'s parameters: the defaults, folding at the tip.
        let mut p = crate::params::ChainParams::default();
        p.record_fold_depth = 0;
        fresh_with_params(p)
    }

    /// [`fresh`] booted on `params` — a pin whose subject needs a governed value at construction (DB-409: a stake lock).
    pub(super) fn fresh_with_params(params: crate::params::ChainParams) -> Arc<Mutex<NodeRuntime<LoopbackTransport>>> {
        use crate::block::{Block, BlockHeader};
        let g = Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&[]),
                nullifier_tags_root: crate::hash::Hash32::hash(&[]),
                output_notes_root: crate::hash::Hash32::hash(&[]),
                // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
                // commitments are the empty-payload hash the verifier re-derives.
                oli_tags_root: crate::block::da_sidecar_root_of(&[]),
                // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
                credit_set_root: crate::block::da_sidecar_root_of(&[]),
                transitions_root: crate::block::empty_transitions_root(),
                cover_seed_commit: crate::hash::Hash32::ZERO,
                member_ring_commit: crate::hash::Hash32::ZERO,
                account_targets_root: crate::block::da_sidecar_root_of(&[]),
                bond_set_root: crate::block::da_sidecar_root_of(&[]),
                dir_set_root: crate::block::da_sidecar_root_of(&[]),
                letter_set_root: crate::block::da_sidecar_root_of(&[]),
                tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
                level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
                version: 1,
                parents: vec![],
                timestamp: 0,
                nonce: 0,
                work: crate::miner::BOOTSTRAP_WORK,
                pow_bind: Hash32::ZERO,
                tx_merkle_root: Hash32::ZERO,
                frontier_root: Hash32::ZERO,
                nullifier_root: Hash32::ZERO,
                sparse_root: Hash32::ZERO,
                chain_acc: [0u8; 16],
                miner_commitment: Hash32::ZERO,
                account_root: Hash32::ZERO,
            },
            tx_ids: vec![],
            pow_proof: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            cover_transition: None,
            member_transition: None,
        };
        let (ta, _tb) = LoopbackTransport::pair();
        Arc::new(Mutex::new(NodeRuntime::new(Node::with_params(g, params).unwrap(), ta)))
    }

    /// ⭐⭐⭐ TWO NODES, ONE ORDINAL, ONE ANSWER — and a GET must actually ASK it.
    ///
    /// ⭐⭐⭐ THE ASSET JOURNEY OVER HTTP — WHAT A REAL USER'S WALLET ACTUALLY DOES.
    ///
    /// ⛔⛔⛔ IN-PROCESS IS NOT A USER. `node::tests::a_user_creates_mints_and_spends_an_asset_and_a_peer_
    /// sees_every_step` proves the journey by calling `Node::publish_asset_*` directly. A person does not
    /// have a `&mut Node` — they have a wallet that speaks HTTP. A route that nothing exercises is the
    /// same class of gap as a module nothing calls (§AN) and a claim nothing proves (§AR): the mechanism
    /// can be perfect and still be unreachable.
    ///
    /// So this drives `route()` — the real dispatcher, the real JSON parsing, the real refusal codes — for
    /// CREATE and MINT, the two classes that had no door at all until 2026-09-13.
    ///
    /// ⭐ It asserts the REFUSALS too: a malformed body must come back 400 and a mint whose carrier does
    /// not open its note must come back 422. A door that only accepts is not a door.
    #[test]
    fn a_user_creates_and_mints_an_asset_over_the_real_http_route() {
        let rt = fresh_testnet();

        // ── CREATE, exactly as a wallet would post it ────────────────────────────────────────────────
        // ⭐ THE CALLER SUPPLIES THE CREATING KEY. The node must never invent one — an asset whose
        // creator the node chose would be an asset the node could mint into.
        let (creator_pk, creator_sk) = crate::pqauth::ml_dsa_keypair();
        // ⭐ §BR-14: the creation carries its fee burn, built the way the creator's wallet builds it — over a USDm note the
        // wallet holds on this node (funded and folded first), so the route verifies a real burn, not a placeholder.
        let fee = {
            let mut c = crate::asset_tx::AssetCreateTx {
                kind: crate::asset_tx::AssetKind::Token,
                symbol: "HTTP".into(),
                name: "Http Token".into(),
                logo: [0u8; 32],
                bytecode: crate::dsol::compile(crate::dsol::DsolKind::Token, "HTTP", "Http Token").bytecode,
                creator: crate::pqauth::pubkey_id(&creator_pk),
                asset_id: [0u8; 32],
                fee: crate::asset_tx::CreationFee::default(),
                art: Vec::new(),
                supply: None,
            };
            c.asset_id = c.derived_id();
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let n = g.node_mut();
            let _ = crate::node::objects::asset_tx::fund_creation_fee_note_for_test(n, &mut [], &c, 0x477, 1_000);
            crate::node::objects::asset_tx::creation_fee_leg_for_test(n, &c, 0x477)
        };
        let fee_fields = format!(
            "\"fee_nullifier\":\"{}\",\"fee_leaf_commit\":\"{}\",\"fee_carrier_hex\":\"{}\",\"fee_membership_carrier_hex\":\"{}\",\
             \"fee_membership_tip_hex\":\"{}\",\"fee_change_note_hex\":\"{}\",\"fee_change_clue_hex\":\"{}\"",
            hex_encode(&fee.nullifier),
            hex_encode(&fee.leaf_commit),
            hex_encode(&fee.carrier),
            hex_encode(&fee.membership_carrier),
            hex_encode(&fee.membership_tip),
            hex_encode(&fee.change_note),
            hex_encode(&fee.change_clue)
        );
        let (code, body) = route(
            &rt,
            "POST",
            "/submit_asset_create",
            &format!(
                "{{\"kind\":\"token\",\"symbol\":\"HTTP\",\"name\":\"Http Token\",\"creator_pubkey\":\"{}\",{fee_fields}}}",
                hex_encode(&creator_pk)
            ),
        );
        assert_eq!(code, 200, "an honest creation must be admitted over HTTP: {body}");
        assert!(
            body.contains("\"verdict\":\"PUBLISHED\""),
            "the route must say plainly that the creation was PUBLISHED, not applied: {body}"
        );
        // ⭐ THE ID COMES BACK, because a user cannot mint into an asset whose id they were never told.
        let asset_id = body
            .split("\"asset_id\":\"")
            .nth(1)
            .and_then(|t| t.split('"').next())
            .map(|h| h.to_string())
            .expect("the creation answers with the id every node recomputes");
        assert_eq!(asset_id.len(), 64, "the id is a 32-byte hex digest: {asset_id}");

        // ⛔ AND A MALFORMED CREATION IS REFUSED, not defaulted into some asset nobody asked for.
        let (bad, _) = route(&rt, "POST", "/submit_asset_create", "{\"kind\":\"token\"}");
        assert_eq!(bad, 400, "a creation with no symbol or name must be refused, never defaulted");
        // ⛔⛔⛔ AND A CREATION NAMING NO CREATOR IS REFUSED. An ownerless asset is one anyone may mint.
        let (no_creator, _) = route(
            &rt,
            "POST",
            "/submit_asset_create",
            "{\"kind\":\"token\",\"symbol\":\"NOC\",\"name\":\"No Creator\"}",
        );
        assert_eq!(
            no_creator, 400,
            "a creation with no creator key must be refused — an asset with no owner can be minted by \
             anyone, which is exactly the hole the creator field closes"
        );

        // ── MINT, against the id the chain just handed back ──────────────────────────────────────────
        let id_bytes: [u8; 32] = <[u8; 32]>::try_from(hex_decode(&asset_id).unwrap().as_slice()).unwrap();
        let tag = usdm_decider::whir_rec_block::wrapped_asset_tag(&id_bytes);
        let sk = usdm_decider::poseidon2_compress::lanes_of(&[31, 32, 33, 34]);
        let (carrier, cm) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_bytes(500, tag, &sk)
                .expect("an honest mint proves");
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..crate::spend_frontier::NOTE_CM_BYTES]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
        // DB-273 §19.6 L3: the note's owner is an OLI clue, and the creator signs its digest.
        let clue = vec![0x5au8; crate::peg_in_tx::OWNER_CLUE_MAX];
        let mint_sig = crate::pqauth::ml_dsa_sign(
            &crate::asset_tx::asset_mint_msg(
                &id_bytes,
                500,
                &crate::spend_frontier::leaf_to_cm_bytes(cm),
                &crate::oli::owner_clue_digest(&clue),
                "",
            ),
            &creator_sk,
        )
        .expect("the creator signs its own mint");
        let body_with = |amount: u64, clue: Option<&[u8]>| {
            let clue_field = match clue {
                Some(c) => format!(",\"note_clue_hex\":\"{}\"", hex_encode(c)),
                None => String::new(),
            };
            format!(
                "{{\"asset_id\":\"{asset_id}\",\"kind\":\"token\",\"amount\":{amount},\"note_hex\":\"{}\",\"mint_carrier_hex\":\"{}\",\"creator_pubkey\":\"{}\",\"creator_sig\":\"{}\",\"symbol\":\"HTTP\",\"asset_name\":\"Http Token\"{clue_field}}}",
                hex_encode(&note),
                hex_encode(&carrier),
                hex_encode(&creator_pk),
                hex_encode(&mint_sig)
            )
        };
        // ⛔ DB-273 §19.6 L3 — a mint naming NO owner is malformed, and a mint whose owner clue is not the one the
        // creator signed is refused: an owner a relay can swap is an owner the creator never chose.
        let (no_owner, _) = route(&rt, "POST", "/submit_asset_mint", &body_with(500, None));
        assert_eq!(no_owner, 400, "⛔ a mint naming no owner was not refused as malformed");
        let (swapped, sbody) = route(&rt, "POST", "/submit_asset_mint", &body_with(500, Some(&[0x77u8; 64])));
        assert_eq!(swapped, 422, "⛔ a mint whose owner clue the creator never signed was admitted: {sbody}");
        let mint_body = body_with(500, Some(&clue));
        let (mcode, mbody) = route(&rt, "POST", "/submit_asset_mint", &mint_body);
        assert_eq!(mcode, 200, "an honest mint must be admitted over HTTP: {mbody}");

        // ⛔⛔⛔ AND A MINT WHOSE CARRIER DOES NOT OPEN ITS NOTE IS REFUSED — otherwise the caller picks
        // its own amount, which is the whole reason the carrier exists.
        let forged = body_with(999_999, Some(&clue));
        let (fcode, fbody) = route(&rt, "POST", "/submit_asset_mint", &forged);
        assert_eq!(
            fcode, 422,
            "⛔⛔⛔ A MINT CLAIMING AN AMOUNT ITS CARRIER DOES NOT OPEN WAS ADMITTED OVER HTTP: {fbody}"
        );
    }

    /// `route()` used to `split('?')` and throw the query away, so `/membership_transition?ordinal=N` parsed
    /// no ordinal, fell to `unwrap_or(0)`, and answered with GENESIS' transition under `"status":"OK"` for
    /// EVERY N — measured live against two running nodes: ordinals 1000, 20000, 30000 and 999999999 all
    /// returned the same block root, each echoing `"ordinal":0`.
    ///
    /// That is the failure this project keeps paying for: not an error, but a well-formed WRONG answer that a
    /// caller cannot tell from a right one. A wallet placing a note or stepping a carrier from it binds to a
    /// block it never asked about — the same shape as serving a copath for slot 0 when the note sits at slot
    /// 187, and as the faucet reading `to` from a query the page never sent.
    ///
    /// Two parties are required to state the property at all: a producer and a verifying peer that ingested
    /// the same blocks must return the SAME transition for the SAME ordinal, and it must be the transition of
    /// the block at that ordinal rather than genesis'. One node asserting against itself cannot distinguish
    /// "both are right" from "both are the same constant".
    #[test]
    fn two_nodes_answer_a_membership_transition_query_identically_and_never_substitute_genesis() {
        let producer = fresh();
        let verifier = fresh();
        let mut blocks = Vec::new();
        {
            let mut p = producer.lock().unwrap();
            for i in 0..4u64 {
                let blk = p
                    .node_mut()
                    .produce(5_000 + i * 500, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
                    .expect("produced");
                blocks.push(blk);
            }
        }
        {
            let mut v = verifier.lock().unwrap();
            for b in &blocks {
                v.node_mut().ingest_block(b.clone(), 9_000);
            }
        }

        let genesis = {
            let (code, j) = route(&producer, "GET", "/membership_transition?ordinal=0", "");
            assert_eq!(code, 200, "{j}");
            j
        };
        let g_root = json_str_field(&genesis, "block_root_hex").expect("genesis root");

        let mut distinct = 0usize;
        for ord in 1..=3u64 {
            let (ca, a) = route(
                &producer,
                "GET",
                &format!("/membership_transition?ordinal={ord}"),
                "",
            );
            let (cb, b) = route(
                &verifier,
                "GET",
                &format!("/membership_transition?ordinal={ord}"),
                "",
            );
            assert_eq!(ca, 200, "producer refused ordinal {ord}: {a}");
            assert_eq!(cb, 200, "verifier refused ordinal {ord}: {b}");
            // The node must ANSWER THE QUESTION ASKED, not silently renumber it to 0.
            assert!(
                a.contains(&format!("\"ordinal\":{ord}")),
                "producer echoed a DIFFERENT ordinal than the query asked for — the query string was dropped: {a}"
            );
            let ra = json_str_field(&a, "block_root_hex").expect("producer root");
            let rb = json_str_field(&b, "block_root_hex").expect("verifier root");
            assert_eq!(ra, rb, "two nodes disagree on the block at ordinal {ord}");
            if ra != g_root {
                distinct += 1;
            }
        }
        assert!(
            distinct > 0,
            "every ordinal returned GENESIS' transition — the node is serving a constant, not an answer"
        );
    }

    /// ⭐⭐⭐ ITEM-12 PIN (server half): ONE batched `/get_my_pq_notes` request serves every named
    /// position, each note carrying its record ADDRESS and SLOT explicitly, and a request wider
    /// than the protocol constant is refused WHOLE.
    ///
    /// WHAT IT CATCHES (and how RED was confirmed): before the batch lane, a `positions` body fell
    /// through to the generic pager, which answers `notes:[{height,blob_hex}]` with NO `batch` key
    /// and NO per-note record address or slot — so the wallet had to issue its per-position asks as
    /// 64 SERIAL round-trips (`OLI_FETCH_PAGES = 64`), and any reader deriving the slot from array
    /// position is the measured lib.rs fund-loss class. RED: with the `positions` reader
    /// neutralized (`has_positions` forced false — the pre-fix routing), every batch-shape assert
    /// below FAILS. GREEN as written.
    ///
    /// FIX-ROUND PINS (20260905), each with its own RED shape:
    ///   • SLOT IS REQUIRED: a batch position naming no `slot` refuses the WHOLE batch
    ///     (`BATCH_POSITION_NAMES_NO_SLOT`) — pre-fix it served ALL 256 slots (~295 KB cloned per
    ///     position under ONE rt-lock hold; ~18.9 MB for 64 such positions). RED: revert the
    ///     `slot.is_none()` guard in the handler and the slotless-refusal assert below FAILS (the
    ///     reply answers the batch shape with 256 notes instead).
    ///   • ROUTING NEEDS BOTH FIELDS: the batch arm is taken only when `positions` is present AND
    ///     `by_record_id:true` — the documented contract shape. RED: revert the gate to
    ///     `if has_positions` alone and the no-flag assert below FAILS (a flagless `positions` body
    ///     answers the batch shape instead of the generic pager).
    ///
    /// ROOT-LAYER: this route is where the reply bytes are PRODUCED; the wallet half of item 12
    /// reads exactly this shape. MUST-STAY-GREEN: the single-position `by_record_id` reply shape
    /// (untouched — the live wallet parses it), `get_info_route_returns_live_json`.
    /// ⭐ DB-223 Q2 §11 (a) RED->GREEN: a `by_ordinal` ask resolves each FOLD ORDINAL through the node's ordinal
    /// map ONLY and answers the row with the record address it resolved to. RED before (a): the batch arm read
    /// every id through the ordinal map and, on a miss, as a raw address — so a record ADDRESS sent as an
    /// ordinal was served as that record (one number read in two spaces), and the unresolved row echoed the
    /// ordinal as its address. Door checklist (§9.6), vs its parallel `by_record_id`: no PoW/proof (it serves
    /// bytes the node already accepted); conservation/replay n/a (read-only); bounded work = the same
    /// `PQ_NOTES_BATCH_FIXED_COUNT` width gate + `want_record_at_ordinal`'s past-tip refusal and
    /// `TX_REQ_FIXED_COUNT` set bound; parity = the slot-required and width refusals run before the branch.
    /// TWO-PARTY-REVIEWED: this pin is the SERVING half of a node→wallet boundary; the wallet half consumes
    /// exactly this row shape in `db223_q2_an_ordinal_located_note_is_filed_at_the_record_address_its_row_resolved`
    /// (monerousd-wallet-v2 lib.rs), and that a producer and a verifying peer fold one record at ONE ordinal is
    /// asserted by `a_late_clue_is_findable_through_the_real_oli_pir_routes_on_a_verifying_peer` (its §11 (a)
    /// amendment). NOT by `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`, which compares
    /// the record each ordinal names on A with the same ADDRESS on B and never B's ordinal of it.
    #[test]
    fn db223_q2_a_by_ordinal_ask_resolves_ordinals_only_and_names_the_record_address() {
        let node = fresh_testnet();
        let note = vec![0x5Au8; 1153];
        let (_blk, seq) = node.lock().unwrap().node_mut().carry_notes_in_a_block_for_test(5_000, &note);
        let mut filler = vec![0u8; 1153];
        filler[31] = 0xD3;
        node.lock().unwrap().node_mut().carry_notes_in_a_block_for_test(6_000, &filler);
        let ord = node.lock().unwrap().node().da_record_ordinal(seq).expect("the carried record folded at the tip");
        assert_ne!(ord, seq, "premise: the two coordinates differ, or this pin cannot tell them apart");
        // The first ordinal no record holds yet — past every folded record (the filler folded at `ord + 1`).
        let absent = node.lock().unwrap().node().da_highest_record_ordinal().expect("records folded") + 1;
        let body = format!(
            "{{\"by_ordinal\":true,\"positions\":[{{\"id\":{ord},\"slot\":0}},{{\"id\":{absent},\"slot\":0}},{{\"id\":{seq},\"slot\":0}}]}}"
        );
        let (code, j) = route(&node, "POST", "/get_my_pq_notes", &body);
        assert_eq!(code, 200);
        assert!(
            j.contains(&format!("\"req\":{ord},\"record_addr\":{seq},\"pending\":false")),
            "the ordinal resolves to its record and the row names that address: {j}"
        );
        assert!(j.contains(&hex_encode(&note)), "the note at (ordinal, slot 0) rides: {j}");
        assert!(
            j.contains(&format!("\"req\":{absent},\"record_addr\":{},\"pending\":true", u64::MAX)),
            "an ordinal this node has not folded is pending and names NO address — never the ordinal: {j}"
        );
        assert!(
            j.contains(&format!("\"req\":{seq},\"record_addr\":{},\"pending\":true", u64::MAX)),
            "a record ADDRESS sent as an ordinal is never read as an address: {j}"
        );
        let wants = node.lock().unwrap().node().wanted_ordinals_for_test();
        assert!(!wants.contains(&seq), "an address past the tip is refused as a want, never admitted: {wants:?}");
        // The whole-record door speaks the same coordinate: `/da_record` by ordinal names the address it resolved.
        let (_, d) = route(&node, "POST", "/da_record", &format!("{{\"ordinal\":{ord}}}"));
        assert!(d.contains(&format!("\"record_addr\":{seq},")), "the whole record names its address: {}", &d[..d.len().min(200)]);
        assert!(d.contains(&hex_encode(&note)), "and carries the record's note");
        let (_, d2) = route(&node, "POST", "/da_record", &format!("{{\"ordinal\":{seq}}}"));
        assert_eq!(d2, "{\"status\":\"OK\",\"notes_hex\":\"\"}", "an ADDRESS sent as an ordinal names nothing");
        let (c3, d3) = route(&node, "POST", "/da_record", "{}");
        assert_eq!(c3, 400, "a request naming no record is refused, never read as record 0: {d3}");
        assert!(d3.contains("DA_RECORD_NAMES_NO_RECORD"), "the refusal names itself: {d3}");
    }

    #[test]
    fn item12_a_batched_by_record_id_request_serves_every_named_slot_with_its_record_address() {
        let rt = fresh();
        let note = |seed: u8| -> Vec<u8> {
            (0..1153u32).map(|i| (i as u8).wrapping_mul(3).wrapping_add(seed)).collect()
        };
        let pa: Vec<u8> = [note(1), note(2)].concat();
        let pb: Vec<u8> = [note(3), note(4)].concat();
        let bid_a = Hash32::hash(b"item12-block-A");
        let bid_b = Hash32::hash(b"item12-block-B");
        let (ra, rb) = {
            let mut g = rt.lock().unwrap();
            let ra = g.node_mut().record_note_payload_for(Some(bid_a), 1, &pa, Some(crate::cover::TEST_COVER_KEY));
            let rb = g.node_mut().record_note_payload_for(Some(bid_b), 2, &pb, Some(crate::cover::TEST_COVER_KEY));
            (ra, rb)
        };
        // ONE request, three positions: (ra slot 1), (rb slot 0), and an ABSENT record — every
        // position names its slot (the contract; the wallet reader always holds one).
        let body = format!(
            "{{\"by_record_id\":true,\"positions\":[{{\"id\":{ra},\"slot\":1}},{{\"id\":{rb},\"slot\":0}},{{\"id\":424242,\"slot\":0}}]}}"
        );
        let (code, j) = route(&rt, "POST", "/get_my_pq_notes", &body);
        assert_eq!(code, 200);
        assert!(j.contains("\"batch\":["), "the batched serve must answer the batch shape: {j}");
        // Each served note names its record address AND slot EXPLICITLY.
        assert!(
            j.contains(&format!("\"record_addr\":{ra},\"slot\":1")),
            "ra's note must carry record_addr + slot explicitly: {j}"
        );
        assert!(
            j.contains(&format!("\"record_addr\":{rb},\"slot\":0")),
            "rb's note must carry record_addr + slot explicitly: {j}"
        );
        // Slot addressing serves the RIGHT bytes: slot 1 of pa, and never slot 0's bytes for it.
        assert!(j.contains(&hex_encode(&pa[1153..2306])), "slot 1's sealed note rides");
        assert!(
            !j.contains(&hex_encode(&pa[..1153])),
            "slot 0 of record A was not asked for and must not ride"
        );
        assert!(j.contains(&hex_encode(&pb[..1153])), "record B slot 0 rides");
        // The absent position is honestly pending — never a silent empty OK.
        assert!(
            j.contains("\"req\":424242,\"record_addr\":424242,\"pending\":true"),
            "an absent record answers pending:true so the wallet holds its cursor: {j}"
        );
        // Width is the PROTOCOL constant: one past it refuses the WHOLE request, loudly.
        let too_many: String = (0..=crate::protocol::PQ_NOTES_BATCH_FIXED_COUNT)
            .map(|i| format!("{{\"id\":{i}}}"))
            .collect::<Vec<_>>()
            .join(",");
        let (c2, j2) = route(
            &rt,
            "POST",
            "/get_my_pq_notes",
            &format!("{{\"by_record_id\":true,\"positions\":[{too_many}]}}"),
        );
        assert_eq!(c2, 200);
        assert!(
            j2.contains("BATCH_WIDER_THAN_PROTOCOL_CONSTANT"),
            "a batch past the protocol constant is refused whole and loudly: {j2}"
        );
        assert!(!j2.contains("\"batch\":["), "an over-wide batch must never be partially served");
        // And a malformed position (no id) refuses the whole batch too.
        let (_, j3) = route(
            &rt,
            "POST",
            "/get_my_pq_notes",
            "{\"by_record_id\":true,\"positions\":[{\"slot\":3}]}",
        );
        assert!(
            j3.contains("MALFORMED_POSITIONS"),
            "a position without an id refuses the whole batch: {j3}"
        );
        // FIX-ROUND PIN: a position naming NO slot refuses the WHOLE batch loudly — pre-fix it
        // served all 256 slots (~295 KB cloned per position under one rt-lock hold). RED: revert
        // the `slot.is_none()` guard and this answers the batch shape instead of the refusal.
        let (_, j4) = route(
            &rt,
            "POST",
            "/get_my_pq_notes",
            &format!("{{\"by_record_id\":true,\"positions\":[{{\"id\":{ra}}}]}}"),
        );
        assert!(
            j4.contains("BATCH_POSITION_NAMES_NO_SLOT"),
            "a slotless batch position must refuse the whole batch, never serve all 256 slots: {j4}"
        );
        assert!(!j4.contains("\"batch\":["), "a slotless batch must never be served: {j4}");
        // FIX-ROUND PIN: the batch arm requires BOTH `positions` AND `by_record_id:true` — the
        // documented contract shape the wallet reader speaks. RED: revert the routing gate to
        // `if has_positions` alone and this flagless body answers the batch shape.
        let (_, j5) = route(
            &rt,
            "POST",
            "/get_my_pq_notes",
            &format!("{{\"positions\":[{{\"id\":{ra},\"slot\":1}}]}}"),
        );
        assert!(
            !j5.contains("\"batch\":["),
            "a positions body WITHOUT by_record_id:true must not take the batch arm: {j5}"
        );
    }

    /// ⭐ ADJACENT DEFECT (b) OF THE 2026-09-05 GATE — `missing_records` AT THE CAP IS A SATURATED
    /// BOUND, NOT A DEBT SIZE, AND /get_info MUST SAY WHICH.
    ///
    /// ROOT-LAYER: every want set is refused at `TX_REQ_FIXED_COUNT` by its own insert site (here
    /// `want_record_at_id`, node.rs), so a full set silently discards each further want; the SUM
    /// `missing_records` cannot express that, and the roll gate reads the sum. The fix is to serve
    /// the five addends beside the cap so saturation is a READ, not an inference.
    /// MEASURED 2026-09-05 (ecosystem gate step 3, scratch /tmp/musd-ecocheck-D6U9H2): both nodes
    /// pinned at `missing_records` 33 for ~7 minutes; the peer had registered 136 distinct copath
    /// wants and 104 of them were refused at the cap — the served 33 understated the debt roughly
    /// four-fold with nothing on the wire able to say so.
    /// MEASURED HERE: 40 distinct record ids are named; the set admits exactly `TX_REQ_FIXED_COUNT`
    /// (32), `missing_by_record_id` reads 32, and `missing_wants_saturated` flips true — the two
    /// states the single old number conflated.
    /// MUST-STAY-GREEN: `get_info_route_returns_live_json` (the roll-gate field pin) and the
    /// rpc_http route-table sweep — this adds fields beside `missing_records`, never in place of it.
    /// RED before the fix: /get_info served only `missing_records`, so a reader at 32 could not tell
    /// a full-and-refusing set from 32 distinct debts, and these two assertions have nothing to read.
    /// O(1): each field is one `len()` of a set the node already maintains, bounded by the protocol
    /// constant — no walk, no term in height, blocks or notes.
    #[test]
    fn get_info_names_a_saturated_want_set_apart_from_a_debt_of_that_size() {
        let rt = fresh();
        let cap = crate::protocol::TX_REQ_FIXED_COUNT;
        // A fresh node owes nothing: every addend zero, nothing saturated, the cap served as the
        // protocol's own request width.
        let (code0, j0) = route(&rt, "GET", "/get_info", "");
        assert_eq!(code0, 200);
        assert!(j0.contains("\"missing_by_ordinal\":0"), "fresh node: {j0}");
        assert!(j0.contains("\"missing_by_record_id\":0"), "fresh node: {j0}");
        assert!(j0.contains("\"missing_da_by_id\":0"), "fresh node: {j0}");
        assert!(j0.contains("\"missing_da_by_ordinal\":0"), "fresh node: {j0}");
        assert!(j0.contains("\"missing_spendfold_gap\":0"), "fresh node: {j0}");
        assert!(j0.contains("\"missing_wants_saturated\":false"), "fresh node: {j0}");
        assert!(
            j0.contains(&format!("\"missing_want_cap\":{cap}")),
            "the served cap must be the protocol's own request width: {j0}"
        );
        {
            let mut g = rt.lock().unwrap();
            let mut k = 0u64;
            // 40 > the cap: the last eight are refused at the door, exactly as the gate's 104 were.
            // A fixed 40 named ids — a request-width constant, never a term in history.
            // DB-227: filled through the HELD-BLOCK door, whose cap is the one under test. The outside
            // door (`want_record_at_id`) now wants only records this node can place, so 40 invented ids
            // would — correctly — raise nothing there (pinned in `db227_…`).
            while k < 40 {
                g.node_mut().want_held_block_record(900_000 + k);
                k += 1;
            }
        }
        let (code, json) = route(&rt, "GET", "/get_info", "");
        assert_eq!(code, 200);
        assert!(
            json.contains(&format!("\"missing_by_record_id\":{cap}")),
            "the by-record-id want set must report itself AT the cap after 40 distinct wants: {json}"
        );
        assert!(
            json.contains("\"missing_wants_saturated\":true"),
            "a want set standing at its cap must be served as SATURATED — otherwise the count reads \
             as a debt size and the roll gate waits for a number that cannot move: {json}"
        );
        assert!(
            json.contains(&format!("\"missing_records\":{cap}")),
            "the sum stays exactly what it was — the split is served beside it, never instead: {json}"
        );
    }

    /// ⛔⛔⛔ DB-229 PIN — EVERY ROOT /get_info SERVES SITS UNDER ITS OWN NAME.
    ///
    /// The ecosystem gate, the real-node pins and every operator read consensus roots from this door by
    /// KEY, so a value one slot to the left is a lie to all of them at once. MEASURED 2026-09-26: the
    /// registry root had been appended after `nullifier_root()` while its key sat before
    /// `membership_acc`, so `unspent_root` served the token registry root (all-zero on an asset-free
    /// chain — the gate's step-3 "roots EQUAL" could not fail), `membership_acc` served the nullifier
    /// root, and `token_registry_root` served the membership accumulator (128 hex chars where a 32-byte
    /// root is 64). ROOT-LAYER: the serializer's argument list is the only place a value meets its name.
    ///
    /// ⛔ CALIBRATION FIRST: a swap is only detectable if the swapped values DIFFER, so the fixture makes
    /// all three roots distinct and non-zero (blocks advance the accumulator and the nullifier root; one
    /// registered asset moves the registry off zero) and asserts that before reading the door.
    /// cons: none — a fixed three-block fixture and one registration, f(fixed constants); test-only, it
    /// adds no production work and no term in height, blocks or notes.
    #[test]
    fn get_info_serves_every_root_under_its_own_name() {
        let rt = fresh();
        {
            let mut g = rt.lock().unwrap();
            for i in 0..3u64 {
                g.node_mut()
                    .produce(5_000 + i * 500, Hash32::hash(b"fr"), Hash32::hash(b"mc"))
                    .expect("produced");
            }
            let c = crate::dsol::compile(crate::dsol::DsolKind::Generic, "ROOTS", "roots under their names");
            g.node_mut().register_dsol_asset(&crate::dsol::DsolContract {
                id: c.id,
                version: c.version,
                kind: crate::dsol::DsolKind::Generic,
                symbol: c.symbol,
                name: c.name,
                verified: false,
                logo: Hash32::ZERO,
            });
        }
        let (registry, membership, unspent) = {
            let g = rt.lock().unwrap();
            (
                g.node().token_registry_root().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                g.node().membership_acc().iter().map(|w| format!("{w:016x}")).collect::<String>(),
                g.node().nullifier_root().iter().map(|b| format!("{b:02x}")).collect::<String>(),
            )
        };
        let zero_like = |s: &str| s.chars().all(|c| c == '0');
        assert!(
            !zero_like(&registry) && !zero_like(&membership) && !zero_like(&unspent),
            "⛔ CALIBRATION: every root must be non-zero or a swap between two zeros is invisible \
             (registry {registry}, membership {membership}, unspent {unspent})"
        );
        assert!(
            registry != membership && registry != unspent && membership != unspent,
            "⛔ CALIBRATION: the three roots must differ or a swap between two equal values is invisible"
        );
        let (code, info) = route(&rt, "GET", "/get_info", "");
        assert_eq!(code, 200);
        let served = |key: &str| -> String {
            let needle = format!("\"{key}\":\"");
            let at = info.find(&needle).map(|i| i + needle.len()).expect("the key is served");
            let rest = &info[at..];
            rest[..rest.find('"').expect("the value is a closed string")].to_string()
        };
        assert_eq!(served("token_registry_root"), registry, "token_registry_root must be the registry root");
        assert_eq!(served("membership_acc"), membership, "membership_acc must be the membership accumulator");
        assert_eq!(served("unspent_root"), unspent, "unspent_root must be the nullifier (unspent-set) root");
    }

    /// ⛔⛔⛔ DB-227 PIN — A WALLET'S COVER POSITIONS MUST NOT BECOME WANTS THAT NO PEER CAN ANSWER.
    ///
    /// Driven through the REAL `/get_my_pq_notes` batch door the wallet speaks, on a node whose ordinal
    /// index holds no rows at the cover ordinals (a restarted or jumped node before its sidecar lane
    /// refills — gate I's node 1). The wallet's batch carries 64 positions: its reals as record addresses
    /// and its cover as ordinals `mod top`.
    /// ROOT-LAYER: the want is produced at `Node::want_record_at_id`, the door every outside position
    /// passes; this pin drives it through the route that feeds it, so a caller-side filter could not
    /// pass it while the door still admitted phantoms from its other callers.
    /// MEASURED: before — gate I step 3 (2026-09-26, scratch musd-ecocheck-2rTkuw): `missing_by_record_id`
    /// pinned at 32 on the restarted node for 7 minutes, the peer answering `asked 32, hold 0`, and
    /// `serve_ready` false throughout. On the pre-DB-227 door this pin registers 32 (the cap) of the 64
    /// cover values and `missing_records` reads 32.
    /// MUST-STAY-GREEN: a record this node PLACES (its ordinal row exists, from a sidecar page) but holds
    /// no bytes for is still wanted — through the resolver's own miss arm, by its ADDRESS — and still
    /// counted, so a real hole keeps the node honestly not ready (the calibration arm below).
    #[test]
    fn db227_cover_positions_on_a_holed_index_raise_no_want_and_a_placed_debt_still_does() {
        let rt = fresh();
        let positions: Vec<String> = (1u64..=64)
            .map(|c| format!("{{\"id\":{c},\"slot\":{}}}", c % 256))
            .collect();
        let body = format!(
            "{{\"by_record_id\":true,\"from_height\":1,\"positions\":[{}]}}",
            positions.join(",")
        );
        let (code, _reply) = route(&rt, "POST", "/get_my_pq_notes", &body);
        assert_eq!(code, 200);
        let (_, info) = route(&rt, "GET", "/get_info", "");
        assert!(
            info.contains("\"missing_by_record_id\":0") && info.contains("\"missing_da_by_id\":0"),
            "64 cover ordinals this node holds no row at named NOTHING it can place — wanting them by id \
             asks peers for keys no by-id serve holds (gate I: `asked 32, hold 0`) and pins readiness: {info}"
        );
        assert!(
            info.contains("\"missing_records\":0"),
            "the cover must not read as ledger debt: {info}"
        );

        // A PLACED record with no bytes: its row lands the way the sidecar lane files it. The wallet names
        // it (by address, as its reals are named) and the want must be raised and counted.
        let placed_rid: u64 = 101_696_601_318_141_276; // a record address from gate I, as a wallet names it
        {
            let mut g = rt.lock().unwrap();
            assert!(g.node_mut().adopt_sidecar_row(7, placed_rid), "a fresh row files at a free slot");
        }
        let body = format!(
            "{{\"by_record_id\":true,\"from_height\":{placed_rid},\"positions\":[{{\"id\":{placed_rid},\"slot\":0}}]}}"
        );
        let (code, _reply) = route(&rt, "POST", "/get_my_pq_notes", &body);
        assert_eq!(code, 200);
        let (_, info) = route(&rt, "GET", "/get_info", "");
        let missing: Option<u64> = info
            .split("\"missing_records\":")
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse::<u64>().ok());
        assert!(
            matches!(missing, Some(m) if m >= 1),
            "⛔ CALIBRATION: a record this node places but holds no bytes for is a REAL debt — the fix must \
             not have silenced it (a node that hides a hole reads ready over a missing note): {info}"
        );
        let g = rt.lock().unwrap();
        assert!(
            g.node().wanted_record_ids().contains(&placed_rid),
            "the placed record is wanted BY ITS ADDRESS — the key a peer's by-id serve can answer"
        );
    }

    /// ⭐⭐⭐ PRODUCTION PATH — `/get_nf_unspent_acc` serves the LIVE O(1) A_tip (the endpoint a wallet's absence
    /// carrier binds to). Driven through the REAL `route()` dispatcher (the same one `handle_conn` calls), NOT the
    /// bare node method: advance A_tip over a few folds, hit the route, and assert the served `a_tip_hex` is the
    /// exact LE-limb encoding of `node.nf_unspent_acc()` + `blocks` == the applied-block count. A genesis node
    /// serves the all-zero seed; after folds it serves the advanced value (never stale, never all-zero).
    #[test]
    fn a_membership_carrier_alone_does_not_authorise_a_spend() {
        // ⛔ THE CARRIER IS NOT YET LOAD-BEARING, AND THAT MUST BE ENFORCED, NOT ASSUMED.
        //
        // `verify_membership_carrier` proves a note is a member of this chain. It does NOT prove that note is
        // the one the spend is spending: `membership_leaf_commit` is supplied by the prover, and
        // `NoteMemberStepGate` constrains `refold(leaf, copath) == block_root` WITHOUT constraining
        // `leaf_commit == Poseidon(leaf, binder)`. A spender could hold a valid carrier for note X and spend
        // note Y. The in-circuit equality is what closes that, and until it lands the depth-32 anchor
        // (`spend_frontier_root`) is what actually authorises a spend.
        //
        // This test exists so nobody — including me on a later pass — reads "membership gate wired" and
        // deletes the wallet's copath rebuild on the strength of it. Deleting it now would leave a restored
        // note visible-but-unspendable, which is the fund-loss shape the cardinals forbid.
        let rt = fresh();

        // A tx with NO membership carrier is not refused by the membership gate: cover, coinbase and every
        // non-spend carrier have no note to prove, and the gate must not halt them.
        let body_no_carrier = format!("{{\"tx_as_hex\":\"{}\"}}", hex_encode(&vec![9u8; 96]));
        let (_, json) = route(&rt, "POST", "/submit_pq_tx", &body_no_carrier);
        assert!(
            !json.contains("MEMBERSHIP_PROOF_INVALID"),
            "an absent carrier must not be treated as a failed one — that would halt every non-spend tx; got {json}"
        );

        // A tx WITH a bogus carrier is refused. So the gate's only current power is REFUSAL: it can reject a
        // wrong proof, it cannot admit a spend on the strength of a right one.
        let body_bad = format!(
            "{{\"tx_as_hex\":\"{}\",\"membership_carrier_hex\":\"{}\",\"membership_leaf_commit_hex\":\"{}\"}}",
            hex_encode(&vec![9u8; 96]),
            hex_encode(&vec![0xABu8; 64]),
            hex_encode(&[7u8; 32]),
        );
        let (_, json_bad) = route(&rt, "POST", "/submit_pq_tx", &body_bad);
        assert!(
            json_bad.contains("MEMBERSHIP_PROOF_INVALID"),
            "a present-but-wrong carrier is refused; got {json_bad}"
        );

        // THE POINT: neither tx was ADMITTED. A carrier — valid or not — is not a spend authorisation, so the
        // pool stays empty and no note moved on the strength of one.
        let (_, info) = route(&rt, "GET", "/get_info", "");
        assert!(
            info.contains("\"status\":\"OK\""),
            "node still serving after both refusals (no halt); got {info}"
        );
        assert!(
            !json.contains("\"status\":\"OK\"") || !json_bad.contains("\"status\":\"OK\""),
            "a membership carrier must never be the thing that admits a spend"
        );
    }

    /// ⭐ DB-223 — THE STREAM'S WIRE FORM ROUND-TRIPS: what `POST /path_refresh_stream` answers, parsed by the wallet
    /// book's ONE parser (`member_witness::stream_from_json`), equals exactly the stream the node computed — every entry
    /// (both sides of each merge), the newest ring root and the peaks. Through the REAL `route()` dispatcher.
    /// TWO-PARTY-REVIEWED: the serve half and the parse half are the two sides of the wire; a node and a wallet each run
    /// one, and this asserts they agree byte for byte.
    #[test]
    fn db223_the_path_refresh_stream_route_answers_what_the_book_parses_back_exactly() {
        let rt = fresh();
        {
            let mut g = rt.lock().expect("the runtime lock");
            for i in 0..48u64 {
                g.node_mut()
                    .produce(5_000 + 1_000 * i, crate::hash::Hash32::hash(b"q2-route"), crate::hash::Hash32::hash(b"mc"))
                    .expect("produces");
            }
        }
        let (code, body) = route(&rt, "POST", "/path_refresh_stream", r#"{"since_ordinal":0}"#);
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("the answer is JSON");
        let parsed = crate::member_witness::stream_from_json(&v).expect("the book parses the served answer");
        let direct = rt.lock().expect("the runtime lock").node().path_refresh_stream(0);
        assert!(!direct.entries.is_empty(), "PRECONDITION: the stream carries entries");
        assert_eq!(parsed, direct, "⛔ DB-223: the served stream and the one the book parses differ");
        let (_, bad) = route(&rt, "POST", "/path_refresh_stream", "{}");
        assert!(bad.contains("BAD_REQUEST:SINCE_ORDINAL"), "a request with no cursor is refused: {bad}");
    }

    /// ⭐⭐ DB-413 — THE LOW HALF SERVED WHOLE, through the REAL dispatcher: the params name a held shard, and
    /// `/window_index_table` answers EXACTLY the node's own `WindowIndex::table` at its folded version — every indexed
    /// root decodes from it at its cell — while a shard it does not hold is named, never answered with an empty table.
    /// TAMPER: the served table's cell decodes to the node's root and to no other window's (a moved cell is a wrong root
    /// the wallet's refold refuses; here it must not even match).
    /// TWO-PARTY-REVIEWED: the serve half of the low catch-up; the wallet's `window_catch_up::LowCatchUp` is the other.
    #[test]
    fn db413_the_window_index_table_route_serves_the_nodes_own_shard_table_whole() {
        let rt = fresh();
        {
            let mut g = rt.lock().expect("the runtime lock");
            for i in 0..48u64 {
                g.node_mut()
                    .produce(5_000 + 1_000 * i, crate::hash::Hash32::hash(b"q2-wi"), crate::hash::Hash32::hash(b"mc"))
                    .expect("produces");
            }
        }
        let (code, params) = route(&rt, "POST", "/window_index_params", "{}");
        assert_eq!(code, 200, "{params}");
        let p: serde_json::Value = serde_json::from_str(&params).expect("params JSON");
        let shard = p["held_shards"].as_array().and_then(|a| a.first()).and_then(|v| v.as_u64()).expect("a held shard");
        let (direct, folded, held) = {
            let g = rt.lock().expect("the runtime lock");
            let folded = g.node().window_index_folded_blocks();
            let held: Vec<(usize, usize, crate::spend_frontier::Digest4)> = crate::window_index::windows_in_shard(shard)
                .into_iter()
                .filter_map(|(l, w)| {
                    let root = g.node().window_index().get(l, w)?;
                    crate::window_index::completing_block(l, w | 1).filter(|b| *b < folded)?;
                    Some((l, crate::window_index::locate(l, w)?.1, root))
                })
                .collect();
            (g.node().window_index().table(shard, folded), folded, held)
        };
        assert!(held.len() >= 40, "PRECONDITION: the held shard holds the windows 48 records completed: {}", held.len());
        let (code, body) = route(&rt, "POST", "/window_index_table", &format!("{{\"shard\":{shard}}}"));
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("table JSON");
        assert_eq!(v["version"].as_u64(), Some(folded), "the answer names the version it was cut at");
        let served = hex_decode(v["table_hex"].as_str().expect("a table")).expect("table hex");
        assert_eq!(Some(&served), direct.as_ref(), "⛔ DB-413: the served table is not the node's own shard table");
        assert_eq!(served.len(), crate::window_index::SHARD_COLS * crate::oli::S_ROWS, "one fixed 256 KB shape");
        let col = |cell: usize| {
            let c = cell / crate::window_index::ROOTS_PER_COL;
            &served[c * crate::oli::S_ROWS..(c + 1) * crate::oli::S_ROWS]
        };
        for (l, cell, root) in &held {
            assert_eq!(
                crate::window_index::root_in_column(col(*cell), *cell),
                Some(*root),
                "⛔ DB-413: level {l} cell {cell} of the served table is not the node's indexed root"
            );
        }
        let (a, b) = (&held[0], &held[1]);
        assert_ne!(crate::window_index::root_in_column(col(a.1), a.1), Some(b.2), "CALIBRATION: two cells hold two roots");
        let (_, unheld) = route(&rt, "POST", "/window_index_table", "{\"shard\":999999}");
        assert!(unheld.contains("SHARD_NOT_HELD"), "an unheld shard is named, never an empty table: {unheld}");
        let (_, bad) = route(&rt, "POST", "/window_index_table", "{}");
        assert!(bad.contains("BAD_REQUEST:SHARD"), "a request naming no shard is refused: {bad}");
    }

    /// ⭐ §BR-12 F13 — a fresh node serves the EMPTY contract-state root and an empty transition ring: the words a wallet
    /// verifies an app's manifest against before paying, and the feed a publisher follows. (The ring's content after a
    /// deploy and a call is pinned beside the objects: `dsol_call_tx::ring_tests`.)
    #[test]
    fn f13_the_contract_state_root_and_the_transition_ring_are_served() {
        let rt = fresh();
        let (code, body) = route(&rt, "GET", "/contract_state_root", "");
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        let empty = hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(crate::contract_state::empty_root()));
        assert_eq!(v["root"].as_str(), Some(empty.as_str()), "⛔ a fresh node's contract-state root is the empty root: {body}");
        let (code, body) = route(&rt, "POST", "/contract_leaves_from", r#"{"from":0}"#);
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(v["root"].as_str(), Some(empty.as_str()));
        assert_eq!(v["updates"].as_array().map(Vec::len), Some(0), "⛔ nothing was applied, nothing is served: {body}");
        assert!(v["oldest"].is_null(), "an empty ring names no oldest height: {body}");
    }

    /// ⭐ DB-223 — `/applied_notes_from` answers each entry's `members` (`[[accepted block id, note count], …]`) exactly
    /// as the node splits it: the counts cover `notes_hex` whole, in order, and each id is an accepted block's.
    /// TWO-PARTY-REVIEWED: the serve half of the wallet's arrival split (its parse half is pinned in the wallet crate).
    #[test]
    fn db223_the_applied_notes_route_answers_the_per_block_split_the_node_holds() {
        let rt = fresh();
        {
            let mut g = rt.lock().expect("the runtime lock");
            for i in 0..6u64 {
                g.node_mut()
                    .produce(5_000 + 1_000 * i, crate::hash::Hash32::hash(b"db223-split"), crate::hash::Hash32::hash(b"mc"))
                    .expect("produces");
            }
        }
        let (code, body) = route(&rt, "POST", "/applied_notes_from", r#"{"from_height":0,"max_blocks":64}"#);
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("the answer is JSON");
        let direct = rt.lock().expect("the runtime lock").node().applied_real_note_members_from(0, 64).1;
        let served = v["blocks"].as_array().expect("blocks");
        assert_eq!(served.len(), direct.len(), "PRECONDITION: one served entry per chain entry");
        assert!(
            direct.iter().filter(|(_, _, m)| m.is_some()).count() >= 6,
            "PRECONDITION: every produced block's entry is held and served"
        );
        for (s, (_, id, members)) in served.iter().zip(&direct) {
            assert_eq!(s["id"].as_str(), Some(hex_encode(id.as_bytes()).as_str()), "entries in the node's order");
            let Some(members) = members.as_ref() else {
                // An entry whose notes this node does not hold (genesis carries none as data) waits: both fields null.
                assert!(s["members"].is_null() && s["notes_hex"].is_null(), "⛔ an unheld entry was served as notes: {s}");
                continue;
            };
            let want: Vec<serde_json::Value> = members
                .iter()
                .map(|(b, ns)| serde_json::json!([hex_encode(b.as_bytes()), ns.len()]))
                .collect();
            assert_eq!(s["members"].as_array(), Some(&want), "⛔ DB-223: the served split is not the node's");
            let total: usize = members.iter().map(|(_, ns)| ns.iter().map(Vec::len).sum::<usize>()).sum();
            assert_eq!(s["notes_hex"].as_str().map(str::len), Some(2 * total), "the counts cover notes_hex whole");
        }
    }

    #[test]
    fn the_unbond_route_carries_the_owner_end_to_end_and_refuses_without_one() {
        // ⭐ THE SEAM, not the gate. `NodeRuntime::unbond_validator` used to hardcode `None`, which would have
        // silently defeated the owner requirement for every caller behind it — the wallet could send the
        // fields and the node would still refuse. A gate is only real if the whole path carries the value.
        //
        // Through the REAL `route()` dispatcher, so this proves the wiring rather than the primitive.
        // DB-409 (DECLARED FIXTURE AMENDMENT, assertions unchanged): the door now refuses an unbond before its bond matures,
        // so this wiring pin boots under a governed stake lock of 0 (matured at once) — its subject is the owner's carriage
        // through the route, not the lock (`node::tests::db409_…` holds the lock).
        let rt = fresh_with_params({
            let mut p = crate::params::ChainParams::default();
            p.record_fold_depth = 0;
            p.governance_set_stake_lock_blocks(0);
            p.governance_set_unbonding_blocks(0); // §BR-3 17.2: this fixture's unbonding window is the merge/fold horizon
            p
        });
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let id = crate::pqauth::pubkey_id(&pk);
        // DB-273 §19.3 L2 (DECLARED FIXTURE AMENDMENT, assertions unchanged): the owner is the returned note's OLI clue.
        let owner_clue = vec![0x5Eu8; crate::peg_in_tx::OWNER_CLUE_MAX];

        // DB-258 (DECLARED FIXTURE AMENDMENT, assertions unchanged): V holds an ANCHORED bonding (landing score + locked
        // note, as a bonding block leaves it) and signs the v2 statement over (validator, live bonding, owner). The v1
        // statement named the validator alone, so any relay could re-file the returned note under another owner. The
        // owner-less request below carries the same honest signature with the owner fields STRIPPED.
        let sig_hex = {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let mut locked = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            locked[..32].copy_from_slice(&[0xE5u8; 32]);
            g.node_mut().admit_bond_unverified(id, 5_000, locked, 1);
            let (sig, nonce) = g.node_mut().sign_unbond_for_test(&sk, &id, &owner_clue);
            (hex_encode(&sig), hex_encode(&nonce))
        };
        // DB-258d (DECLARED FIXTURE AMENDMENT, assertions unchanged): the owner request names the nonce V signed.
        let (sig_hex, nonce_hex) = sig_hex;
        let sign_unbond = || -> String { sig_hex.clone() };

        // WITHOUT an owner: refused. The bond stays put rather than being returned somewhere unfindable.
        let body_no_owner = format!(
            "{{\"pubkey\":\"{}\",\"sig\":\"{}\"}}",
            hex_encode(&pk),
            sign_unbond()
        );
        let (code, j) = route(&rt, "POST", "/unbond_validator", &body_no_owner);
        // ⭐ 422, NOT 200. This asserted `200` carrying `"unbonded":false` — a refusal wearing a success
        // code, which is the same "report a step as an arrival" shape this tree refuses everywhere else
        // (the faucet's `recorded:true` cost a whole diagnosis pass on 2026-09-04). The behaviour is
        // UNCHANGED — an unbond naming no account owner is still refused and the bond still stays put —
        // only the code now says so, so a caller cannot read the refusal as a success.
        assert_eq!(
            code, 422,
            "an unbond naming no account owner must be REFUSED — the returned bond would be \
             undiscoverable: {j}"
        );
        assert!(
            j.contains("UNBOND_NEEDS_AN_OWNER"),
            "and the refusal must NAME its reason, so the caller knows what to supply: {j}"
        );

        // WITH an owner: it goes through. Both halves matter — refusal alone would also "pass" if the route
        // were simply broken, so the success case is what proves the value actually reaches the node.
        let body_owner = format!(
            "{{\"pubkey\":\"{}\",\"sig\":\"{}\",\"nonce_hex\":\"{}\",\"note_clue_hex\":\"{}\"}}",
            hex_encode(&pk),
            sign_unbond(),
            nonce_hex,
            hex_encode(&owner_clue)
        );
        let (code2, j2) = route(&rt, "POST", "/unbond_validator", &body_owner);
        assert_eq!(code2, 200);
        // ⭐ PUBLISHED, NOT UNBONDED — §AS. The route used to release the weight and return the note on
        // THIS node and tell nobody (MEASURED: `A weight=0 | B weight=50000`, so the same bond was
        // returnable once per node). It now publishes a framed `Class::Unbond` object; the release
        // happens on EVERY node when a block carrying it grafts. Saying "unbonded" here would be the
        // old claim with the new mechanism underneath it.
        assert!(
            j2.contains("\"verdict\":\"PUBLISHED\""),
            "an unbond that NAMES its owner must be admitted to the pool so it can travel: {j2}"
        );
    }

    #[test]
    fn note_copath_serves_the_append_ordinal_so_a_wallet_can_place_its_note_without_the_stream() {
        // ⭐ THE LAST DATUM. A note's depth-32 copath needs its GLOBAL leaf index = `ordinal*256 + slot`. The
        // record address cannot give the ordinal (addresses derive from block ids, not from write order), so
        // `fetch_all_note_cms` counted the entire stream to recover it. Serving it here is what lets a wallet
        // place its note with two constant-size fetches instead.
        //
        // Through the REAL `route()` dispatcher, so this proves the field is WIRED, not merely computed.
        // TWO PARTIES. The ordinal is only useful if the RECIPIENT's node places a note where the sender's
        // node did — a copath built at a different index folds to a different root, so the note would be
        // visible and unspendable. Both runtimes write the same records; both must serve the same positions.
        let rt = fresh_testnet();
        let peer = fresh_testnet();
        // v31: three notes ride three produced blocks on `rt`; the peer grafts the same blocks
        let mut carried: Vec<(crate::block::Block, u64)> = Vec::new();
        {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            for h in 1..4u64 {
                let mut note = vec![0u8; 1153];
                note[0] = 0x40 + h as u8;
                carried.push(g.node_mut().carry_notes_in_a_block_for_test(5_000 + h * 1_000, &note));
            }
        }
        {
            let mut p = peer.lock().unwrap_or_else(|e| e.into_inner());
            for (h, (blk, _)) in carried.iter().enumerate() {
                assert!(
                    matches!(p.node_mut().ingest_block(blk.clone(), 5_500 + h as u64 * 1_000), crate::relay::RelayOutcome::Added(_)),
                    "the peer grafts block {h}"
                );
            }
        }

        let addr1 = carried[0].1;
        let addr3 = carried[2].1;

        let ask_on = |r: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>, addr: u64| -> String {
            let mut raw = addr.to_le_bytes().to_vec();
            raw.push(0u8);
            let (code, json) = route(
                r,
                "POST",
                "/note_copath",
                &format!("{{\"positions_hex\":\"{}\"}}", hex_encode(&raw)),
            );
            assert_eq!(code, 200);
            json
        };
        let ask = |addr: u64| -> String {
            let mut raw = addr.to_le_bytes().to_vec();
            raw.push(0u8);
            let (code, json) = route(
                &rt,
                "POST",
                "/note_copath",
                &format!("{{\"positions_hex\":\"{}\"}}", hex_encode(&raw)),
            );
            assert_eq!(code, 200);
            json
        };

        let j1 = ask(addr1);
        assert!(
            j1.contains("\"ordinal\":"),
            "the copath response must carry the append ordinal; got {j1}"
        );
        let ord_of = |j: &str| -> i64 {
            let k = j.find("\"ordinal\":").expect("ordinal present") + 10;
            let rest = &j[k..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '-')
                .unwrap_or(rest.len());
            rest[..end].parse().expect("ordinal parses")
        };
        let o1 = ord_of(&j1);
        let o3 = ord_of(&ask(addr3));
        assert!(
            o1 >= 0 && o3 >= 0,
            "records this node wrote have real ordinals, got {o1} and {o3}"
        );
        assert!(
            o3 > o1,
            "ordinals follow WRITE order — record 3 was appended after record 1 ({o1} -> {o3})"
        );

        // A record this node never wrote reports -1, not a guessed position: a wrong ordinal yields a copath
        // that cannot fold to the live root, which reads as unspendable rather than unknown.
        let missing = crate::node::Node::da_record_id(9_999, 0);
        let jm = ask(missing);
        assert!(
            jm.contains("null") || ord_of(&jm) == -1,
            "an unwritten record must not be given a position; got {jm}"
        );

        // THE CROSS-NODE ASSERTION: the peer that wrote the same records must serve the SAME positions.
        // Without this the recipient builds a copath at a different index and its note, though visible,
        // could never be spent.
        assert_eq!(
            ord_of(&ask_on(&peer, addr1)),
            o1,
            "a peer holding the same records must place record 1 at the same append ordinal"
        );
        assert_eq!(
            ord_of(&ask_on(&peer, addr3)),
            o3,
            "and record 3 too — a recipient's copath index must match the sender's"
        );
        assert_eq!(
            ask_on(&peer, addr1),
            ask(addr1),
            "the whole served copath must be byte-identical across the two nodes"
        );
    }

    #[test]
    fn the_membership_gate_refuses_a_bad_carrier_through_the_real_submit_route() {
        // PRODUCTION PATH, not a bare fn: this goes through `route()` — the same dispatcher a wallet's HTTP
        // POST lands on — so it proves the gate is WIRED, not merely that the verifier exists.
        //
        // The gate is the replacement for the depth-32 copath a wallet could only rebuild by paging the whole
        // note stream. What must never happen is a spender getting a bogus membership proof admitted, so the
        // decisive assertion is the REJECTION: a carrier that is present and does not verify is refused
        // fail-closed, on that tx alone, with the chain unaffected.
        let rt = fresh();

        // The route serves the tip a carrier must land on, at constant size and at any height.
        let (code, json) = route(&rt, "GET", "/get_membership_acc", "");
        assert_eq!(code, 200);
        for f in ["genesis_acc_hex", "tip_prev_hex", "tip_root_hex", "acc_hex"] {
            assert!(
                json.contains(f),
                "the carrier endpoint must serve {f}; got {json}"
            );
        }
        // RAW LANES: `DIGEST_LANE_BYTES` zero bytes, i.e. twice that many hex zeros — never a literal 64.
        let zero_hex = "0".repeat(2 * crate::spend_frontier::DIGEST_LANE_BYTES);
        assert!(
            json.contains(&format!("\"genesis_acc_hex\":\"{zero_hex}\"")),
            "the fold START is pinned to the chain's, so a carrier cannot name its own; got {json}"
        );

        // A PRESENT-but-bogus carrier must be refused by the real route.
        let body = format!(
            "{{\"tx_as_hex\":\"{}\",\"membership_carrier_hex\":\"{}\",\"membership_leaf_commit_hex\":\"{}\"}}",
            hex_encode(&vec![9u8; 96]),
            hex_encode(&vec![0xABu8; 64]),
            hex_encode(&[7u8; 32]),
        );
        let (code, json) = route(&rt, "POST", "/submit_pq_tx", &body);
        assert_eq!(code, 200);
        assert!(
            json.contains("MEMBERSHIP_PROOF_INVALID"),
            "a carried membership proof that does not verify must be refused FAIL-CLOSED; got {json}"
        );

        // And the refusal is scoped to that tx: the node's own accumulator is untouched, so one bad spend
        // cannot move consensus state or halt the chain.
        let (code2, json2) = route(&rt, "GET", "/get_membership_acc", "");
        assert_eq!(code2, 200);
        assert!(
            json2.contains(&format!("\"acc_hex\":\"{zero_hex}\"")),
            "a rejected tx must leave the accumulator exactly where it was; got {json2}"
        );
    }

    #[test]
    fn a_stale_carrier_settles_through_the_real_submit_route_on_a_chain_that_kept_producing() {
        // ⭐ THE GATE MUST ADMIT, NOT ONLY REFUSE. Its neighbour proves a bogus carrier is rejected; that is
        // only half a gate, and a gate that rejects EVERYTHING passes that half perfectly. This proves the
        // other half on the production path: a carrier built against an earlier tip, submitted after the
        // chain moved on, is ADMITTED — which is the ordinary case for every real spend, since building a
        // carrier takes seconds and the tip moves every block.
        //
        // TWO PARTIES: the carrier is built from what one runtime SERVES over its routes and settled by a
        // SECOND runtime that ingested the same blocks. A one-runtime version could not tell a working gate
        // from one that merely agrees with itself.
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        let server = fresh();
        let settler = fresh();

        let mine = |rt: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>, i: u64| {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut()
                .produce(5_000 + i * 500, Hash32::ZERO, Hash32::ZERO)
                .expect("produced")
        };
        let give = |rt: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>, b: crate::block::Block| {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut().ingest_block(b, 9_000);
        };

        for i in 0..2u64 {
            give(&settler, mine(&server, i));
        }

        // Everything below comes off the ROUTES a wallet actually calls — no direct Node access.
        // The membership family's ONE decoder (raw lanes) — exactly what a wallet must call on every
        // field these routes serve. §AG class 9 lived here as a hand-rolled eight-lane walk that PANICKED
        // on the 32-byte values the routes used to serve.
        let parse4 = |h: &str| -> crate::spend_frontier::Digest4 {
            let b = hex_decode(h).expect("served hex");
            crate::spend_frontier::digest_from_lane_bytes(&b)
                .unwrap_or_else(|| panic!("a served digest must be exactly one raw-lane slot; got {} bytes", b.len()))
        };
        let field = |json: &str, key: &str| -> String {
            let at = json
                .find(&format!("\"{key}\":\""))
                .unwrap_or_else(|| panic!("{key} in {json}"));
            let rest = &json[at + key.len() + 4..];
            rest[..rest.find('"').unwrap()].to_string()
        };

        let (_, acc_json) = route(&server, "GET", "/get_membership_acc", "");
        let start = parse4(&field(&acc_json, "genesis_acc_hex"));

        // The roots to fold, and the ORDINAL of the last one — the endpoint the carrier will name.
        let (_, roots_json) = route(&server, "POST", "/membership_roots", "{\"from_topo\":0}");
        let mut roots: Vec<crate::spend_frontier::Digest4> = Vec::new();
        let mut last_ord = 0u64;
        for chunk in roots_json.split("{\"topo\":").skip(1) {
            let ord: u64 = chunk[..chunk.find(',').unwrap()]
                .parse()
                .expect("an ordinal");
            let rh = field(chunk, "root_hex");
            last_ord = ord;
            roots.push(parse4(&rh));
        }
        assert!(
            roots.len() >= 2,
            "the server must serve the roots it folded; got {roots_json}"
        );

        // This note's in-block copath, from the same routes. The subject is the FIRST record that
        // CONTRIBUTES to the membership accumulator — ordinal 1. Ordinal 0 is genesis's, by the
        // settled 2026-09-05 law (`ensure_genesis_ordinal` / `fold_canonical_records`): genesis
        // contributes NO leaves, NO accumulator step and NO served root, so `/membership_roots`
        // begins at ordinal 1 (`membership_roots_from`: "the stream begins at the first position
        // that contributes one") and no carrier can — or ever needs to — certify membership under
        // the genesis record: no fund rides it (its only note is the ownerless public seed).
        // MEASURED 2026-09-06: with the subject at ordinal 0 this pin failed 5/5 at finalize with
        // the `!saw_want` discriminator — want_root (genesis's record root) is absent from the
        // served series BY THE CHAIN'S LAW, not by any gate defect. The pin's claim (a STALE
        // carrier for a real record settles through the real route) is unchanged; only its subject
        // had silently slipped onto genesis when ordinal 0 became genesis's position.
        let (seq, slot) = {
            let g = server.lock().unwrap_or_else(|e| e.into_inner());
            let s = g
                .node()
                .da_addr_at_ordinal(1)
                .expect("the server holds ordinal 1 — the first contributing record");
            (s, 0u8)
        };
        let mut pos = Vec::new();
        pos.extend_from_slice(&seq.to_le_bytes());
        pos.push(slot);
        let (_, cp_json) = route(
            &server,
            "POST",
            "/note_copath",
            &format!("{{\"positions_hex\":\"{}\"}}", hex_encode(&pos)),
        );
        let sibs: Vec<crate::spend_frontier::Digest4> = {
            let sh = field(&cp_json, "siblings_hex");
            sh.as_bytes()
                .chunks(2 * crate::spend_frontier::DIGEST_LANE_BYTES)
                .map(|c| parse4(std::str::from_utf8(c).unwrap()))
                .collect()
        };
        let dirs: Vec<bool> = field(&cp_json, "dirs").chars().map(|c| c == '1').collect();
        let want_root = parse4(&field(&cp_json, "block_root_hex"));
        let leaf = {
            let g = server.lock().unwrap_or_else(|e| e.into_inner());
            g.node().da_block_leaves(seq).expect("leaves")[slot as usize]
        };

        let binder =
            crate::spend_frontier::cm_bytes_to_leaf(Hash32::hash(b"route-stale-nf").as_bytes());
        let mut carrier = NoteMembershipCarrier::new(leaf, want_root, start, binder, crate::spend_frontier::TEST_LC_BLIND);
        assert!(
            carrier.attach_membership(leaf, &sibs, &dirs),
            "the SERVED copath must attach"
        );
        // DB-213c: the ONE-STEP form — the note's own record root, folded once, proven directly. The
        // served roots stay fetched: the calibration above asserts the server serves what it folded.
        let _ = &roots;
        assert!(carrier.step(want_root), "the note's own record root folds");
        let commit = carrier.leaf_commitment();
        // `finalize_detail`, not `finalize`: same conditions, same order, same success value — only
        // the failure NAMES which half broke (`!saw_want` = input selection vs no-proof = prover
        // fault). This is a diagnosis upgrade, never a rescue: it panics on exactly the inputs the
        // bare `expect("certified")` panicked on.
        // ROOT-LAYER: the carrier is where certification is produced — the discriminator lives in
        // `finalize_detail` (note_membership_air.rs) and only this call site can surface it.
        // MEASURED: 5/5 red runs saying only "panicked … certified" (scratchpad/fail-92.log,
        // 2026-09-06) -> one run naming "want_root was NEVER among the roots folded", which located
        // the genesis-subject drift immediately.
        // MUST-STAY-GREEN: this very pin plus its refusal sibling (`…refused_by_the_real_route`) —
        // nothing is accepted that was refused before.
        let (proof, acc, tip_prev, tip_root) = carrier
            .finalize_one_step()
            .unwrap_or_else(|e| panic!("certified: {e}"));
        // The THREE-slot tip (prev ‖ root ‖ acc) in raw lanes, and the leaf commit in its canonical
        // 32-byte form — the two encoders the gate's decoders are the inverses of. The leaf commit was
        // built from the digest's lanes 0..3 only (the other half of §AG class 9: a silently half-width
        // value), so the gate could never recover the commitment the carrier bound.
        let mut tip_bytes = Vec::with_capacity(4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8);
        for d in [start, tip_prev, tip_root, acc] {
            tip_bytes.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
        }
        tip_bytes.extend_from_slice(&seq.to_le_bytes());
        // The SAME proof in the removed THREE-lane layout — must be refused (DB-213c).
        let mut three_lane = Vec::with_capacity(3 * crate::spend_frontier::DIGEST_LANE_BYTES);
        for d in [tip_prev, tip_root, acc] {
            three_lane.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
        }
        let commit_b = crate::spend_frontier::leaf_to_cm_bytes(commit);

        // ⏱ THE CHAIN MOVES ON, exactly as it does while a real spender is proving.
        for i in 2..5u64 {
            give(&settler, mine(&server, i));
        }

        let submit = |rt: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>,
                      tip_hex: &str,
                      through: u64|
         -> String {
            // ⭐ DB-331: the spend's nullifier rides the body — the one-step gate takes its BINDER from it
            // (DB-217/218), and this pin predated that: with no `nullifier_hex` the gate refused every carrier
            // before verifying one. `leaf_to_cm_bytes(binder)` is the canonical form the gate decodes.
            let body = format!(
                "{{\"tx_as_hex\":\"{}\",\"membership_carrier_hex\":\"{}\",\
                 \"membership_leaf_commit_hex\":\"{}\",\"membership_tip_hex\":\"{}\",\
                 \"membership_folded_through\":{},\"nullifier_hex\":\"{}\"}}",
                hex_encode(&vec![9u8; 96]),
                hex_encode(&proof),
                hex_encode(&commit_b),
                tip_hex,
                through,
                hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(binder)),
            );
            route(rt, "POST", "/submit_pq_tx", &body).1
        };

        // ⭐ STALE SETTLES, through the real route, on the node that only VERIFIED these blocks. The tx itself
        // is a stub and is refused for its own reasons — what must not appear is the MEMBERSHIP refusal.
        let out = submit(&settler, &hex_encode(&tip_bytes), last_ord);
        assert!(
            !out.contains("MEMBERSHIP_PROOF_INVALID"),
            "a carrier built against an EARLIER tip must still pass the membership gate — the node closes \
             the gap from its own roots. got {out}"
        );

        // ⛔ AND THE ENDPOINT IS MANDATORY. A carrier with no named endpoint leaves the node nothing to
        // reconstruct from, and it must refuse rather than quietly substituting its own tip — which would
        // make the gate verify the proof against whatever the node already believes.
        let out = submit(&settler, "", last_ord);
        assert!(
            out.contains("MEMBERSHIP_PROOF_INVALID"),
            "a carrier that names no endpoint must be refused fail-closed; got {out}"
        );

        // ⛔ AND A FORGED LANDING STILL REJECTS through the route: settling stale carriers must not settle
        // invented ones.
        let out = submit(&settler, &hex_encode(&three_lane), last_ord);
        assert!(
            out.contains("MEMBERSHIP_PROOF_INVALID"),
            "⛔ the removed THREE-lane layout must be refused — it has no sound verifier (DB-213c); got {out}"
        );

        let mut forged = tip_bytes.clone();
        forged[3 * crate::spend_frontier::DIGEST_LANE_BYTES] ^= 1; // the first byte of the accumulator slot
        let out = submit(&settler, &hex_encode(&forged), last_ord);
        assert!(
            out.contains("MEMBERSHIP_PROOF_INVALID"),
            "an accumulator this chain never reached must be refused; got {out}"
        );
    }

    /// ⭐ A FRESH PAYMENT IS LOCATABLE ON A YOUNG CHAIN (user 2026-11-03: "The cash layer must be ironclad"). The real-pair
    /// sequence, in-process through `route()`: the wallet asks BEFORE its note exists (the node builds and caches an index of 0
    /// tags, as at boot), then the note lands on a chain far short of one `EPOCH_BLOCKS` boundary, and the SERVED shard table
    /// must then hold its key. RED-first on the 64-block floor: the boot index stayed served for the chain's first 64 records
    /// (MEASURED on a real pair, lane cashfirst: credit carried and folded, tip 40 → 88, `[oli-build] … (0 tag(s))` the whole
    /// run, the payer read 0). Two runtimes: the clue reaches a VERIFYING peer, the party whose index lacked it.
    #[test]
    fn a_note_recorded_before_the_first_epoch_boundary_is_in_the_served_index() {
        let producer = fresh_testnet();
        let verifier = fresh_testnet();
        let loc_sk = crate::oli::derive_loc_sk(blake3::hash(b"MUSD/oli/young-chain/recipient").as_bytes());
        let addr = crate::address::pq_stealth_address_v3(
            1,
            &[3u8; 32],
            &vec![0x11u8; crate::address::MLKEM_EK_LEN],
            &crate::oli::locator_at(&loc_sk, "recv", 0),
            &crate::oli::address_salt(&loc_sk, "recv", 0),
            &crate::oli::address_index_hint(&loc_sk, &crate::oli::address_salt(&loc_sk, "recv", 0), 0),
        )
        .expect("a v3 receive address");
        let parsed = crate::address::parse_address_full(&addr).expect("a payer parses it");
        let clue = crate::oli::tag_clue_bytes_v2(
            &parsed.locator.expect("locator"),
            &parsed.loc_salt.expect("salt"),
            &parsed.loc_hint.expect("hint"),
        );
        let k = crate::oli::index_key(&clue);
        let ask_params = || -> String {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            loop {
                let (code, params) = route(&verifier, "GET", "/oli_params", "");
                if code == 200 {
                    return params;
                }
                assert!(code == 503 && params.contains("BUILDING"), "/oli_params: {code} {params}");
                assert!(std::time::Instant::now() < deadline, "/oli_params never built in 120 s: {params}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        };
        // the wallet asks first, before its note exists — the index the node builds now holds 0 tags
        let _ = ask_params();

        let note = vec![0x5Bu8; 1153];
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&note[0..32]);
        let (blk1, _) = {
            let mut g = producer.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut().carry_notes_in_a_block_for_test(5_000, &note)
        };
        {
            let mut g = verifier.lock().unwrap_or_else(|e| e.into_inner());
            assert!(matches!(g.node_mut().ingest_block(blk1, 5_500), crate::relay::RelayOutcome::Added(_)), "graft block 1");
        }
        const YOUNG: u64 = 8; // far short of one EPOCH_BLOCKS boundary
        assert!(YOUNG < crate::oli::EPOCH_BLOCKS);
        for h in 2..YOUNG {
            let mut filler = vec![0u8; 1153];
            filler[..8].copy_from_slice(&h.to_le_bytes());
            filler[31] = 0xC1;
            let (blk, _) = {
                let mut g = producer.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().carry_notes_in_a_block_for_test(5_000 + h * 1_000, &filler)
            };
            let mut g = verifier.lock().unwrap_or_else(|e| e.into_inner());
            assert!(matches!(g.node_mut().ingest_block(blk, 5_500 + h * 1_000), crate::relay::RelayOutcome::Added(_)), "graft block {h}");
        }
        {
            let mut g = verifier.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut().record_note_clue(cm, clue);
            assert!(g.node().served_block_count() < crate::oli::EPOCH_BLOCKS, "calibration: the chain is younger than one epoch");
        }
        // the served table must now hold the key — re-asked as the production client re-asks while a build lands
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let params = ask_params();
            let shard_bits = json_num_field(&params, "shard_bits").unwrap_or(0) as u32;
            let sid = crate::oli::shard_of(&k, shard_bits);
            let (code, tj) = route(&verifier, "POST", "/oli_table", &format!("{{\"shard\":{sid}}}"));
            assert_eq!(code, 200, "/oli_table: {tj}");
            let key = "\"table_hex\":\"";
            let at = tj.find(key).expect("table_hex");
            let rest = &tj[at + key.len()..];
            let table = hex_decode(&rest[..rest.find('"').unwrap()]).expect("table hex");
            if crate::oli::table_lookup(&table, crate::oli::SHARD_BUCKETS, &k).is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "⛔ a note recorded on a chain younger than one epoch is in NO served table after 120 s — its owner cannot locate it"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    #[test]
    fn a_late_clue_is_findable_through_the_real_oli_pir_routes_on_a_verifying_peer() {
        // ⭐ PRODUCTION PATH, not the function. The unit test proves `attach_tag_to_recorded_block` places the
        // tag; it says NOTHING about whether a wallet can then FIND that note — which crosses `route()`, JSON
        // field names, hex encoding, the served index build, and the PIR answer path. Two wallet sends have
        // already broken at exactly those boundaries with green unit tests behind them.
        //
        // TWO RUNTIMES: the clue is delivered to a VERIFYING peer, not the node that minted the note, because
        // that is the party whose index silently lacked the tag before.
        // ⛔ ON THE TESTNET GENESIS, because a verifier JUDGES the note's justifier: `carry_notes_in_a_block_for_test`
        // stages an unattested BridgeCredit, admissible only inside `genesis_mint_allowance()`, which the bare
        // `fresh()` genesis (empty parity commit) does not have. MEASURED 2026-09-26 (lane-db224-carriage, this
        // tree with and without DB-224): the verifier logged `[graft-door] ⛔ §BA REFUSED a credit-set object that
        // fails this chain's own admission rule` x138, filed no address, and dropped the late clue — the pin was
        // measuring a refused fixture, never the late-clue path. `fresh_testnet` folds at the tip exactly as
        // `fresh` does; only the genesis (and so the allowance) differs.
        let producer = fresh_testnet();
        let verifier = fresh_testnet();

        let loc_sk =
            crate::oli::derive_loc_sk(blake3::hash(b"MUSD/oli/route-late/recipient").as_bytes());
        // ⭐ A FAR SUBADDRESS INDEX, and the tag built the way a real payer builds it: parse the recipient's
        // v3 address, copy its (locator, salt, hint) verbatim. Index 1,000,000 is past ANY enumeration a
        // wallet could do, which is exactly the payment the retired gap limit used to lose.
        const FAR_J: u64 = 1_000_000;
        let addr = crate::address::pq_stealth_address_v3(
            1,
            &[3u8; 32],
            &vec![0x11u8; crate::address::MLKEM_EK_LEN],
            &crate::oli::locator_at(&loc_sk, "recv", FAR_J),
            &crate::oli::address_salt(&loc_sk, "recv", FAR_J),
            &crate::oli::address_index_hint(
                &loc_sk,
                &crate::oli::address_salt(&loc_sk, "recv", FAR_J),
                FAR_J,
            ),
        )
        .expect("the recipient hands out a v3 address at a far subaddress index");
        let parsed = crate::address::parse_address_full(&addr).expect("a payer parses it");
        let clue = crate::oli::tag_clue_bytes_v2(
            &parsed.locator.expect("locator"),
            &parsed.loc_salt.expect("salt"),
            &parsed.loc_hint.expect("hint"),
        );
        // The RECIPIENT recognises its own payment in one step, with no index guessing — the property the
        // whole path below then has to preserve end to end.
        assert_eq!(
            crate::oli::owns_tag(&loc_sk, &["recv", "chg"], &clue),
            Some(("recv".to_string(), FAR_J)),
            "the recipient must recognise a payment to subaddress {FAR_J} from the ADDRESS ALONE"
        );
        let k = crate::oli::index_key(&clue);

        let note = vec![0x5Au8; 1153];
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&note[0..32]);

        // The note's block is recorded on BOTH, with no clue in hand.
        // v31: the producer carries the note in a real block and the verifier grafts the producer's blocks —
        // the only way a verifying peer holds the same ledger.
        let (blk1, seq) = {
            let mut g = producer.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut().carry_notes_in_a_block_for_test(5_000, &note)
        };
        {
            let mut g = verifier.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                matches!(g.node_mut().ingest_block(blk1, 5_500), crate::relay::RelayOutcome::Added(_)),
                "the verifier grafts block 1"
            );
        }
        for h in 2..400u64 {
            let mut filler = vec![0u8; 1153];
            filler[..8].copy_from_slice(&h.to_le_bytes());
            filler[31] = 0xC0;
            let (blk, _) = {
                let mut g = producer.lock().unwrap_or_else(|e| e.into_inner());
                g.node_mut().carry_notes_in_a_block_for_test(5_000 + h * 1_000, &filler)
            };
            let mut g = verifier.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                matches!(g.node_mut().ingest_block(blk, 5_500 + h * 1_000), crate::relay::RelayOutcome::Added(_)),
                "the verifier grafts block {h}"
            );
        }
        {
            let mut g = verifier.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut().record_note_clue(cm, clue);
        }

        // ── EVERYTHING BELOW GOES THROUGH `route()`, exactly as a wallet's HTTP calls do ────────────────
        // DB-107: an epoch's locator index is built OFF the runtime lock, and until it lands `/oli_params` answers
        // 503 `BUILDING … ask again` — the production client re-asks on its next pass. Ask again on wall-clock the
        // same way; any status other than 200 or that 503 still fails here, and so does an index that never lands.
        let params_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let params = loop {
            let (code, params) = route(&verifier, "GET", "/oli_params", "");
            if code == 200 {
                break params;
            }
            assert!(
                code == 503 && params.contains("BUILDING"),
                "/oli_params must answer 200, or 503 BUILDING while the epoch's index is built: {code} {params}"
            );
            assert!(
                std::time::Instant::now() < params_deadline,
                "/oli_params never finished building this epoch's index in 120 s: {params}"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        let shard_bits = json_num_field(&params, "shard_bits").unwrap_or(0) as u32;
        let epoch_hex = {
            let key = "\"epoch_seed\":\"";
            let at = params
                .find(key)
                .unwrap_or_else(|| panic!("epoch_seed_hex in {params}"));
            let rest = &params[at + key.len()..];
            rest[..rest.find('"').unwrap()].to_string()
        };
        let mut epoch = [0u8; 32];
        epoch.copy_from_slice(&hex_decode(&epoch_hex).expect("epoch seed hex"));

        let sid = crate::oli::shard_of(&k, shard_bits);
        let (code, hint_json) = route(
            &verifier,
            "POST",
            "/oli_hint",
            &format!("{{\"shard\":{sid}}}"),
        );
        assert_eq!(code, 200, "/oli_hint must answer: {hint_json}");
        let hint = {
            let key = "\"hint_hex\":\"";
            let at = hint_json.find(key).expect("hint_hex");
            let rest = &hint_json[at + key.len()..];
            hex_decode(&rest[..rest.find('"').unwrap()]).expect("hint hex")
        };
        assert!(!hint.is_empty(), "the served hint must not be empty");

        // The wallet's own 2-choice PIR: one locator is ALWAYS two queries, a constant shape that reveals
        // nothing about where — or whether — the key landed.
        let coords = crate::oli::query_coords(&k, crate::oli::SHARD_BUCKETS);
        let t_cols = (crate::oli::SHARD_BUCKETS as usize) / crate::oli::BUCKETS_PER_COL;
        let mut queries_hex = String::new();
        let mut secrets = Vec::new();
        for (i, (col, _)) in coords.iter().enumerate() {
            let mut r = [0u8; 32];
            r[0] = i as u8 + 1;
            r[31] = 0xA5;
            let (q, sec) = crate::oli::build_query(t_cols, &epoch, *col, &r);
            queries_hex.push_str(&hex_encode(&q));
            secrets.push(sec);
        }
        let (code, ans_json) = route(
            &verifier,
            "POST",
            "/oli_answer",
            &format!("{{\"shard\":{sid},\"queries_hex\":\"{queries_hex}\"}}"),
        );
        assert_eq!(code, 200, "/oli_answer must answer: {ans_json}");
        let answers = {
            let key = "\"answers_hex\":\"";
            let at = ans_json.find(key).expect("answers_hex");
            let rest = &ans_json[at + key.len()..];
            hex_decode(&rest[..rest.find('"').unwrap()]).expect("answers hex")
        };
        // An answer is S_ROWS u32 words (4 bytes each) — the width `recover_bucket` requires.
        let alen = crate::oli::S_ROWS * 4;
        assert_eq!(
            answers.len(),
            alen * 2,
            "one locator is exactly TWO answers, always"
        );

        let bucket_a =
            crate::oli::recover_bucket(&answers[..alen], &hint, &secrets[0], coords[0].1)
                .expect("the first candidate bucket recovers from the SERVED hint + answer");
        let bucket_b =
            crate::oli::recover_bucket(&answers[alen..], &hint, &secrets[1], coords[1].1)
                .expect("the second candidate bucket recovers");
        let hits = crate::oli::probe_candidates(&bucket_a, &bucket_b, &k);

        // ⭐ THE EFFECT MATERIALISED: the note is FINDABLE over the real routes, 398 blocks after its block
        // was recorded. This is what a user's wallet actually does to locate a payment.
        // DECLARED COORDINATE AMENDMENT (DB-223 Q2 §11 (a), 2026-09-29): an index entry names its record by FOLD
        // ORDINAL, so the hit is the record's ordinal — and the producer and the verifying peer fold it at the SAME one.
        // MEASURED: the first (a) run found [(1, 0)] against the record address 136710003825188192 — the ordinal.
        let ord = verifier.lock().unwrap().node().da_record_ordinal(seq).expect("the verifying peer folded the record");
        assert_eq!(
            producer.lock().unwrap().node().da_record_ordinal(seq),
            Some(ord),
            "the producer and the verifying peer fold the record at ONE ordinal"
        );
        assert!(
            hits.iter().any(|(fseq, _slot)| *fseq as u64 == ord),
            "a payment to subaddress {FAR_J}, clued 398 blocks late, must be findable through the REAL \
             /oli_params + /oli_hint + /oli_answer path on a VERIFYING peer. Found {hits:?}, wanted ordinal \
             {ord} (record {seq}). This is the exact payment the retired gap limit lost."
        );

        // FAIL-CLOSED: a locator nobody ever registered must yield NOTHING through the same routes — so the
        // hit above is a real lookup, not a path that returns something for anything.
        let absent = crate::oli::index_key(&crate::oli::tag_clue_bytes(&crate::oli::locator_at(
            &crate::oli::derive_loc_sk(blake3::hash(b"MUSD/oli/route-late/stranger").as_bytes()),
            "recv",
            0,
        )));
        assert!(
            crate::oli::probe_candidates(&bucket_a, &bucket_b, &absent).is_empty(),
            "a locator this chain never carried must resolve to NOTHING — a forged hit would make the \
             assertion above meaningless"
        );
        let _ = producer; // the producer exists to make this two-party; its own index is not the subject
    }

    /// ⭐ DB-228 — THE WHOLE-TABLE LOCATE THROUGH THE REAL ROUTES, AND THE CHAIN KEY A WALLET DERIVES.
    ///
    /// Everything a restoring wallet does on the DB-228 path, through `route()`: read `chain_id` from
    /// `/get_info`, derive the index's chain key with `oli::chain_key`, and accept it ONLY if it reproduces
    /// the `epoch_seed` `/oli_params` serves (the wallet's derivation checked against the node's own
    /// `oli_chain_key` through the wire); fetch the note's shard with `/oli_table`; locate the note in it
    /// with `oli::table_candidates`; and find its position in the chaff-filtered real-entry pool the wallet
    /// draws its fetch cover from.
    /// FAIL-CLOSED ARMS: a request naming no shard is refused (never read as shard 0); an absent key locates
    /// nothing in the same table; an out-of-range shard answers a same-size all-zero table.
    #[test]
    fn db228_the_whole_shard_table_served_by_oli_table_locates_a_note_and_reproduces_the_served_seed() {
        let node = fresh_testnet();
        let loc_sk =
            crate::oli::derive_loc_sk(blake3::hash(b"MUSD/oli/db228-route/recipient").as_bytes());
        let clue = crate::oli::tag_clue_bytes(&crate::oli::locator_at(&loc_sk, "recv", 7));
        let k = crate::oli::index_key(&clue);
        let note = vec![0x6Bu8; 1153];
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&note[0..32]);
        let (_blk, seq) = node.lock().unwrap().node_mut().carry_notes_in_a_block_for_test(5_000, &note);
        // `oli_index` caches ONE (epoch end, index) pair PROCESS-WIDE, so this node is given an epoch end no
        // other route test uses (three epochs and change) and the poll below waits until ITS index is served.
        for h in 2..(3 * crate::oli::EPOCH_BLOCKS + 5) {
            let mut filler = vec![0u8; 1153];
            filler[..8].copy_from_slice(&h.to_le_bytes());
            filler[31] = 0xD2;
            node.lock().unwrap().node_mut().carry_notes_in_a_block_for_test(5_000 + h * 1_000, &filler);
        }
        assert!(
            node.lock().unwrap().node_mut().record_note_clue(cm, clue.clone()),
            "the locator clue attaches to the recorded note"
        );
        // DECLARED COORDINATE AMENDMENT (DB-223 Q2 §11 (a), 2026-09-29): an index entry names its note by FOLD
        // ORDINAL, so the note is located at its record's ordinal — never at the record address `seq`.
        let ord = node.lock().unwrap().node().da_record_ordinal(seq).expect("the carried record folded at the tip");

        let (code, info) = route(&node, "GET", "/get_info", "");
        assert_eq!(code, 200, "/get_info must answer: {info}");
        let chain_hex = json_str_field(&info, "chain_id").expect("/get_info serves chain_id");
        let genesis: [u8; 32] = hex_decode(&chain_hex)
            .expect("chain_id is hex")
            .try_into()
            .expect("chain_id is the 32-byte genesis id");
        let ck = crate::oli::chain_key(Some(&genesis));

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let (bits, table) = loop {
            let (pcode, params) = route(&node, "GET", "/oli_params", "");
            if pcode == 200 {
                let bits = json_num_field(&params, "shard_bits").expect("shard_bits") as u32;
                let sid = crate::oli::shard_of(&k, bits);
                let (tcode, tj) = route(&node, "POST", "/oli_table", &format!("{{\"shard\":{sid}}}"));
                if tcode == 200 && json_num_field(&tj, "shard_bits") == Some(bits as u64) {
                    let table = hex_decode(&json_str_field(&tj, "table_hex").expect("table_hex"))
                        .expect("table hex");
                    assert_eq!(
                        table.len(),
                        (crate::oli::SHARD_BUCKETS as usize) * crate::oli::BUCKET_BYTES,
                        "a served table is always the fixed shard size"
                    );
                    if crate::oli::table_candidates(&table, &k).iter().any(|(s, _)| *s == ord) {
                        let seed_hex = json_str_field(&params, "epoch_seed").expect("epoch_seed");
                        assert_eq!(
                            hex_decode(&seed_hex).expect("seed hex"),
                            crate::oli::epoch_seed(&ck).to_vec(),
                            "the chain key a wallet derives from /get_info's chain_id must reproduce the \
                             epoch seed /oli_params serves — two derivations of one value that disagree \
                             mean the wallet and the node key one index differently"
                        );
                        break (bits, table);
                    }
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the note at record {seq} (ordinal {ord}) never became locatable from the /oli_table shard of its key"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let located = crate::oli::table_candidates(&table, &k);
        let pool = crate::oli::table_positions(&table);
        assert!(
            located.iter().all(|p| pool.contains(p)),
            "every located real sits in the served pool — reals and cover share one universe (located {located:?})"
        );

        // FAIL-CLOSED ARMS.
        let (ncode, nj) = route(&node, "POST", "/oli_table", "{}");
        assert_eq!(ncode, 400, "a table request naming no shard is refused, never read as shard 0: {nj}");
        assert!(nj.contains("OLI_TABLE_NAMES_NO_SHARD"), "the refusal names itself: {nj}");
        let absent = crate::oli::index_key(b"MUSD/oli/db228-route/never-paid");
        assert!(
            crate::oli::table_candidates(&table, &absent).is_empty(),
            "a key this chain never carried locates NOTHING in the same table"
        );
        let beyond = 1u64 << bits;
        let (ocode, oj) = route(&node, "POST", "/oli_table", &format!("{{\"shard\":{beyond}}}"));
        assert_eq!(ocode, 200, "an out-of-range shard still answers: {}", &oj[..oj.len().min(200)]);
        let empty = hex_decode(&json_str_field(&oj, "table_hex").expect("table_hex")).expect("hex");
        assert_eq!(empty.len(), table.len(), "same size whether or not the shard holds anything");
        assert!(empty.iter().all(|b| *b == 0), "an out-of-range shard is the all-zero table");
    }

    /// ⛔ THE RETIRED POOL SURFACE ANSWERS WITH A TOMBSTONE, NEVER A SILENT 404 — a caller built
    /// against /amm_pool //submit_amm learns WHY the surface is gone (the pool AMM is retired for the
    /// P2P limit-order DEX) instead of guessing. Pinned so the tombstone cannot rot into a fall-through.
    #[test]
    fn the_retired_amm_routes_answer_gone_with_the_reason() {
        let node = fresh();
        for (m, p) in [("GET", "/amm_pool"), ("POST", "/amm_pool"), ("POST", "/submit_amm")] {
            let (code, json) = route(&node, m, p, "{}");
            assert_eq!(code, 410, "{m} {p} must answer GONE, got {code}: {json}");
            assert!(json.contains("retired"), "{m} {p} tombstone must say why: {json}");
            assert!(json.contains("limit orders"), "{m} {p} tombstone names the successor: {json}");
        }
    }

    /// ⭐⭐⭐ THE WHOLE TRADE, THROUGH THE REAL ROUTES, ACROSS THE SEAM — post → read the book → fill.
    ///
    /// ⛔ THE ONE RULE THAT MAKES THIS TEST WORTH ANYTHING: after posting, the taker builds its fill using
    /// ONLY what `/book_level` SERVED — the maker publics and the payout note are re-parsed out of that
    /// JSON response, never read from the test's own variables. A test that reaches around the wire and
    /// uses its local copies proves the two halves work; it does not prove the HANDOFF works.
    ///
    /// MEASURED 2026-08-31, why this exists: the book served `maker.payout_cm` but not the maker's payout
    /// NOTE BYTES, which only the maker can produce. Every honest fill was refused at settlement and the
    /// whole trade path was a dead end — while the node suite and the wallet suite were BOTH green,
    /// because each tested its own side and neither tested the handoff. Two seam breaks in one day came
    /// through that blind spot. This is the shape that closes it.
    #[test]
    fn a_taker_can_fill_using_only_what_the_book_served_end_to_end_through_the_routes() {
        use usdm_decider::whir_rec_block::{
            prove_order_maker_half, prove_order_taker_half, wrapped_asset_tag_u32, MakerHalfWitness,
            OrderTerms, TakerHalfWitness, USDM_ASSET_TAG,
        };
        // DECLARED FIXTURE AMENDMENT (DB-354's rule): the inputs are planted with an UNATTESTED credit, which only the
        // testnet identity's open-mint allowance admits. On `fresh()` (no allowance) DB-274 P4's fold strips the planted
        // note — MEASURED 2026-09-30 on the pre-§19.6 binary: `[plant] the staged note did not ride the block`, the test
        // red at its PRECONDITION before any fill ran.
        let node = fresh_testnet();

        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: crate::order_book::snap_expiry(500_000),
        };
        let mw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[41, 42, 43, 44])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[51, 52, 53, 54]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
        let (maker_bytes, maker) = prove_order_maker_half(&mw, &t).expect("maker half proves");
        // ⭐ DB-330c: DB-150 made the maker's membership cross-bind a REQUIRED post field, and this fixture never planted
        // the maker's input note — so `/post_order` answered 400 and nothing after it ever ran (measured on testbin-c7).
        // Plant each input note ON CHAIN and bind it, as the node-level settlement fixtures do.
        let plant = |cm: crate::spend_frontier::Digest4, binder: crate::spend_frontier::Digest4, tag: &[u8], at: u64| {
            let mut g = node.lock().unwrap();
            g.node_mut()
                .plant_note_and_bind_for_test(&crate::spend_frontier::leaf_to_cm_bytes(cm), binder, tag, at)
                .map(|(c, tip, _)| (c, tip))
                .expect("PRECONDITION: the input note is planted on chain and bound")
        };
        let (mm_c, mm_t) = plant(
            usdm_decider::whir_rec_block::asset_note_cm(t.lot, t.asset_a, mw.owner.opening()),
            maker.nullifier,
            b"route-maker-input-note",
            60_000,
        );

        let h3 = |v: &[u64; 3]| -> String {
            let mut o = String::new();
            for w in v {
                o.push_str(&hex_encode(&w.to_le_bytes()));
            }
            o
        };
        // The DEX surface's one digest wire form: the canonical 32-byte encoding (`/post_order` and
        // `/submit_order_fill` decode it with `cm_bytes_to_root`; `/book_level` serves it).
        let h4 = |v: &crate::spend_frontier::Digest4| -> String {
            hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(*v))
        };
        // DB-273 §19.6 L3: the maker's own payout owner, posted with the order.
        let maker_payout_clue = vec![0x3Cu8; 96];
        // The maker's payout note, as only the maker can build it: its commitment, then sealed bytes.
        let mut maker_payout_note = vec![0u8; 1153];
        maker_payout_note[..32]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm));

        let post_body = format!(
            "{{\"lot\":{},\"pay_b\":{},\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"expires_at_height\":{},\"nullifier\":\"{}\",\"leaf_commit\":\"{}\",\"payout_cm\":\"{}\",\"maker_bytes_hex\":\"{}\",\"payout_note_hex\":\"{}\",\"membership_carrier_hex\":\"{}\",\"membership_tip_hex\":\"{}\",\"payout_clue_hex\":\"{}\"}}",
            t.lot, t.pay_b, h3(&t.asset_a), h3(&t.asset_b), t.expires_at_height,
            h4(&maker.nullifier), h4(&maker.leaf_commit), h4(&maker.payout_cm),
            hex_encode(&maker_bytes), hex_encode(&maker_payout_note),
            hex_encode(&mm_c), hex_encode(&mm_t),
            // DB-273 §19.6 L3: the MAKER names its payout owner at post.
            hex_encode(&maker_payout_clue)
        );
        let (pc, pj) = route(&node, "POST", "/post_order", &post_body);
        assert_eq!(pc, 200, "the order must rest: {pj}");

        // ── THE SEAM. Everything below comes out of the BOOK's own answer. ──
        let level_body = format!(
            "{{\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"level\":{}}}",
            h3(&t.asset_a),
            h3(&t.asset_b),
            crate::order_book::RestingOrder {
                terms: t,
                maker,
                maker_bytes: maker_bytes.clone(),
                payout_note: maker_payout_note.clone(),
                membership_carrier: Vec::new(),
                membership_tip: Vec::new(),
                payout_clue: Vec::new(), // `.level()` reads the terms only
            }
            .level()
        );
        let (lc, served) = route(&node, "POST", "/book_level", &level_body);
        assert_eq!(lc, 200, "the level must serve: {served}");

        // Pull each field back out of the served JSON — this is what a real taker has, and nothing else.
        let field = |src: &str, name: &str| -> String {
            let pat = format!("\"{name}\":\"");
            let a = src.find(&pat).unwrap_or_else(|| panic!("book did not serve {name}: {src}"))
                + pat.len();
            let b = src[a..].find('"').expect("unterminated field") + a;
            src[a..b].to_string()
        };
        let served_maker_bytes = field(&served, "maker_bytes_hex");
        let served_nullifier = field(&served, "nullifier");
        let served_leaf_commit = field(&served, "leaf_commit");
        let served_payout_cm = field(&served, "payout_cm");
        let served_payout_note = field(&served, "payout_note_hex");
        // DB-150: the maker's cross-bind rides the resting order, so a taker takes it from the book too.
        let served_mm_c = field(&served, "membership_carrier_hex");
        let served_mm_t = field(&served, "membership_tip_hex");

        // ⛔ THE ASSERTION THAT WOULD HAVE CAUGHT THE DEAD END: the book must serve the payout NOTE, not
        // just its commitment. Only the maker can produce these bytes, so a taker without them cannot
        // build a submittable fill no matter how correct everything else is.
        assert!(
            !served_payout_note.is_empty(),
            "the book served no payout note — a taker holds a commitment it cannot turn into a note, so \
             every honest fill is refused at settlement and the trade path is a dead end"
        );
        assert_eq!(
            served_payout_note,
            hex_encode(&maker_payout_note),
            "the served payout note must be the maker's own bytes, verbatim"
        );

        // The taker proves its half against the terms the BOOK published.
        let tw = TakerHalfWitness {
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[61, 62, 63, 64])),
            value_in: t.pay_b + 40_000,
            change_opening: usdm_decider::poseidon2_compress::lanes_of(&[71, 72, 73, 74]),
            payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[81, 82, 83, 84]),
            lc_blind: crate::spend_frontier::TEST_LC_BLIND,
        };
        let (taker_bytes, taker) = prove_order_taker_half(&tw, &t, crate::params::ORDER_FILL_FEE_BPS_DEFAULT)
            .expect("taker half proves");
        let (tm_c, tm_t) = plant(
            usdm_decider::whir_rec_block::asset_note_cm(tw.value_in, t.asset_b, tw.owner.opening()),
            taker.nullifier,
            b"route-taker-input-note",
            60_400,
        );
        let note_for = |cm: crate::spend_frontier::Digest4| -> Vec<u8> {
            let mut v = vec![0u8; 1153];
            v[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
            v
        };
        let addr = |seed: u8| -> String {
            crate::address::pq_stealth_address(1, &[seed; 32], &[seed; 1184])
                .expect("a valid stealth address")
        };

        // ⭐ DB-273 §19.6 L3: the body carries the TAKER's clue records the way the wallet's fill door sends them (payout,
        // change — exactly two, in that order). The hostile variant also names the MAKER's payout, which a taker must never
        // choose: the door takes the maker's owner only from the order the maker posted, and refuses a list that is not
        // exactly the taker's two. The body also names a `maker_addr` — a field the door no longer reads at all.
        let leaf = crate::spend_frontier::leaf_to_cm_bytes;
        let clue_list_of = |recs: &[([u8; 32], u8)]| {
            let mut out = Vec::new();
            for (c, b) in recs {
                out.extend_from_slice(c);
                out.extend_from_slice(&96u16.to_le_bytes());
                out.extend_from_slice(&[*b; 96]);
            }
            out
        };
        let hostile_list =
            clue_list_of(&[(leaf(taker.payout_cm), 0xA1), (leaf(taker.change_cm), 0xA2), (leaf(maker.payout_cm), 0xEE)]);
        let clue_list = clue_list_of(&[(leaf(taker.payout_cm), 0xA1), (leaf(taker.change_cm), 0xA2)]);
        let fill_body_with = |clues: &[u8]| format!(
            "{{\"maker_carrier\":\"{}\",\"maker_nullifier\":\"{}\",\"maker_leaf_commit\":\"{}\",\"maker_payout_cm\":\"{}\",\"taker_carrier\":\"{}\",\"taker_nullifier\":\"{}\",\"taker_leaf_commit\":\"{}\",\"taker_change_cm\":\"{}\",\"taker_payout_cm\":\"{}\",\"lot\":{},\"pay_b\":{},\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"expires_at_height\":{},\"maker_payout_note\":\"{}\",\"taker_payout_note\":\"{}\",\"taker_change_note\":\"{}\",\"maker_addr\":\"{}\",\"taker_addr\":\"{}\",\"note_clues_hex\":\"{}\",\"maker_membership_carrier_hex\":\"{}\",\"maker_membership_tip_hex\":\"{}\",\"taker_membership_carrier_hex\":\"{}\",\"taker_membership_tip_hex\":\"{}\"}}",
            served_maker_bytes,
            served_nullifier,
            served_leaf_commit,
            served_payout_cm,
            hex_encode(&taker_bytes),
            h4(&taker.nullifier),
            h4(&taker.leaf_commit),
            h4(&taker.change_cm),
            h4(&taker.payout_cm),
            t.lot,
            t.pay_b,
            h3(&t.asset_a),
            h3(&t.asset_b),
            t.expires_at_height,
            served_payout_note,
            hex_encode(&note_for(taker.payout_cm)),
            hex_encode(&note_for(taker.change_cm)),
            addr(0xA1),
            addr(0xB2),
            hex_encode(clues),
            served_mm_c,
            served_mm_t,
            hex_encode(&tm_c),
            hex_encode(&tm_t)
        );
        // ⛔ A taker naming the MAKER's owner is refused with nothing spent (MISSING_OWNER: its own two are not exactly
        // what it sent), and the order stays fillable.
        let (hc, hj) = route(&node, "POST", "/submit_order_fill", &fill_body_with(&hostile_list));
        assert_eq!(hc, 422, "⛔ DB-273 §19.6 L3: a fill whose clue list names the MAKER's payout was not refused: {hj}");
        let fill_body = fill_body_with(&clue_list);
        let (fc, fj) = route(&node, "POST", "/submit_order_fill", &fill_body);
        assert_eq!(
            fc, 200,
            "A FILL BUILT ONLY FROM WHAT THE BOOK SERVED MUST SETTLE. If this fails, the book is not \
             serving everything a taker needs and the whole trade path is a dead end: {fj}"
        );
        assert!(fj.contains("SETTLED"), "the fill settles: {fj}");
        // ⭐ DB-273 §14.2: the wallet consumes its dense indices ONLY on `clues_filed == 2`, so the reply must state
        // exactly the TAKER's records the settlement carries — and the settlement must carry exactly those.
        assert!(
            fj.contains("\"clues_filed\":2"),
            "⛔ §14.2: the fill door did not state the taker's two filed clues (and must not count the maker's): {fj}"
        );
        // ⭐ DB-273 §19.6 L3: the pooled settlement OBJECT names all three owners — slot 0 the clue the MAKER posted (never
        // the taker's `maker_addr` or any record it sent), slots 1–2 the taker's own — and carries no sidecar at all.
        let (owners, sidecar): (Vec<([u8; 32], Vec<u8>)>, Vec<u8>) = {
            let g = node.lock().unwrap();
            let n = g.node();
            let tx = n
                .mempool()
                .all_tx_ids()
                .iter()
                .filter_map(|id| n.mempool().get(&crate::hash::Hash32(*id)).cloned())
                .find(|t| {
                    crate::chain_object::unframe(&t.blob).map(|(k, _)| k) == Some(crate::chain_object::Class::OrderFill)
                })
                .expect("the settlement is pooled");
            (
                crate::chain_object::object_owner_clue_records(&tx.blob).expect("a fill is owner-named"),
                tx.note_clues.clone(),
            )
        };
        assert_eq!(
            owners,
            vec![
                (leaf(maker.payout_cm), maker_payout_clue.clone()),
                (leaf(taker.payout_cm), vec![0xA1u8; 96]),
                (leaf(taker.change_cm), vec![0xA2u8; 96]),
            ],
            "⛔ DB-273 §19.6 L3: the settlement's owners are not (maker's posted clue, taker's two) in slot order"
        );
        assert!(sidecar.is_empty(), "⛔ DB-273 §19.6 L3: a fill still carries a relay-mutable clue sidecar");

        // ⛔ AND THE FILLED ORDER LEAVES THE BOOK — otherwise every later taker reads a dead offer.
        let (_, after) = route(&node, "POST", "/book_level", &level_body);
        assert!(
            !after.contains(&served_nullifier),
            "the filled order is still being served: {after}"
        );

        // ⛔ A REPLAY OF THE SAME FILL IS REFUSED — the double-spend gate IS the anti-double-fill.
        let (rc, rj) = route(&node, "POST", "/submit_order_fill", &fill_body);
        assert_ne!(rc, 200, "a replayed fill must not settle twice: {rj}");
    }

    /// ⭐⭐⭐ THE BOOK OVER THE WIRE, ON TWO NODES. A maker posts a real order to node A; both nodes must
    /// answer `/book_level` with the SAME constant shape, and the order must be readable back well enough
    /// for a taker to fill it. Two nodes because a book that only works on the node that received the
    /// post is not a book — a taker asks whichever node they are connected to.
    ///
    /// Also pins the privacy shape at the WIRE, not just in the module: `slots` is constant and a level
    /// holding an order answers with the same total shape as one nobody has touched, so polling reveals
    /// neither depth nor activity.
    #[test]
    fn the_book_routes_post_and_serve_a_constant_shape_on_two_nodes_and_refuse_a_forgery() {
        use usdm_decider::whir_rec_block::{
            prove_order_maker_half, wrapped_asset_tag_u32, MakerHalfWitness, OrderTerms,
            USDM_ASSET_TAG,
        };
        // Two INDEPENDENT runtimes, built the way every other route test here builds one.
        // DECLARED FIXTURE AMENDMENT (DB-354's rule, as in `a_taker_can_fill_using_only…`): the maker's input is planted
        // with an UNATTESTED credit, which only the testnet identity's open-mint allowance admits; on `fresh()` DB-274
        // P4's fold strips it and this test was red at its PRECONDITION (MEASURED 2026-09-30).
        let node_a = fresh_testnet();
        let node_b = fresh_testnet();

        // DEX-GRID (C3): through the one snap helper.
        let t = OrderTerms {
            lot: crate::order_book::snap_to_grid(100_000),
            pay_b: crate::order_book::snap_to_grid(250_000),
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: crate::order_book::snap_expiry(500_000),
        };
        let bmw = MakerHalfWitness { owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24])), payout_opening: usdm_decider::poseidon2_compress::lanes_of(&[31, 32, 33, 34]), lc_blind: crate::spend_frontier::TEST_LC_BLIND };
        let (mbytes, maker) = prove_order_maker_half(&bmw, &t).expect("maker half proves");
        // ⭐ DB-330c: DB-150 made the maker's membership cross-bind a REQUIRED post field; this pin died at its first
        // honest post (400) from then on (measured on testbin-c7). The maker's input note is planted on A and bound.
        let (bmm_c, bmm_t, bmm_blk) = {
            let mut g = node_a.lock().unwrap();
            g.node_mut()
                .plant_note_and_bind_for_test(
                    &crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
                        t.lot, t.asset_a, bmw.owner.opening(),
                    )),
                    maker.nullifier,
                    b"book-route-maker-input-note",
                    60_000,
                )
                .expect("PRECONDITION: the maker's input note is planted on A and bound")
        };
        // ⭐ G9: B holds the SAME chain — A's block crosses by the block door and B folds it. DB-407 (5efb48a) made
        // `/post_order` ask the fill door's membership verdict BEFORE the proof verify (Bitcoin Core's order: missing
        // inputs are refused before script verification), so a B that never saw the maker's record answered the
        // retry code 409 MEMBERSHIP_NOT_FOLDED_YET and the forgery never reached the gate this test names.
        {
            let mut g = node_b.lock().unwrap();
            assert!(
                matches!(g.node_mut().ingest_block(bmm_blk, 60_001), crate::relay::RelayOutcome::Added(_)),
                "PRECONDITION: B grafts the block carrying the maker's input note"
            );
            let _ = g.node_mut().fold_canonical_records();
        }

        let h3 = |v: &[u64; 3]| -> String {
            let mut o = String::new();
            for w in v {
                o.push_str(&hex_encode(&w.to_le_bytes()));
            }
            o
        };
        // The DEX surface's one digest wire form: the canonical 32-byte encoding (`/post_order` and
        // `/submit_order_fill` decode it with `cm_bytes_to_root`; `/book_level` serves it).
        let h4 = |v: &crate::spend_frontier::Digest4| -> String {
            hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(*v))
        };
        let post_body = format!(
            "{{\"lot\":{},\"pay_b\":{},\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"expires_at_height\":{},\"nullifier\":\"{}\",\"leaf_commit\":\"{}\",\"payout_cm\":\"{}\",\"maker_bytes_hex\":\"{}\",\"payout_note_hex\":\"{}\",\"membership_carrier_hex\":\"{}\",\"membership_tip_hex\":\"{}\",\"payout_clue_hex\":\"{}\"}}",
            t.lot,
            t.pay_b,
            h3(&t.asset_a),
            h3(&t.asset_b),
            t.expires_at_height,
            h4(&maker.nullifier),
            h4(&maker.leaf_commit),
            h4(&maker.payout_cm),
            hex_encode(&mbytes),
            // ⭐ AN HONEST ORDER CARRIES ITS OWN PAYOUT NOTE. The book serves these bytes so a taker can
            // build the payload settlement binds to `payout_cm`; an order without them is unfillable, so
            // the route refuses it at POST rather than letting a taker discover it at fill.
            hex_encode(&{
                let mut n = vec![0u8; 1153];
                n[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm));
                n
            }),
            hex_encode(&bmm_c),
            hex_encode(&bmm_t),
            // DB-273 §19.6 L3: the maker's payout owner, posted with the order.
            hex_encode(&[0x3Cu8; 96])
        );

        let (code, json) = route(&node_a, "POST", "/post_order", &post_body);
        assert_eq!(code, 200, "an honest order must rest: {json}");
        assert!(json.contains("\"resting\":true"), "{json}");

        // A malformed post is a 400 and rests nothing; a FORGED proof is a 422 naming its gate.
        let (bad, _) = route(&node_a, "POST", "/post_order", "{}");
        assert_eq!(bad, 400, "a post with no fields must be refused, never defaulted");
        let forged_body = post_body.replace(
            &hex_encode(&mbytes),
            &hex_encode(&{
                let mut c = mbytes.clone();
                c[0] ^= 0xFF;
                c
            }),
        );
        // The forgery goes to node B, which holds no order — otherwise A refuses it as a DUPLICATE
        // (the cheap nullifier check correctly runs before the expensive proof verify) and the test would
        // never reach the gate it means to exercise. This also proves B refuses a forgery INDEPENDENTLY:
        // every node stands behind its own book rather than trusting what a peer accepted.
        let (fcode, fjson) = route(&node_b, "POST", "/post_order", &forged_body);
        assert_eq!(fcode, 422, "a forged maker half must be refused: {fjson}");
        assert!(fjson.contains("PROOF_REFUSED"), "the refusal names its gate: {fjson}");

        // Read the level back on BOTH nodes. A serves the order; B has never seen it — but both must
        // answer with the SAME constant slot shape.
        let level_body = format!(
            "{{\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"level\":{}}}",
            h3(&t.asset_a),
            h3(&t.asset_b),
            crate::order_book::RestingOrder {
                terms: t,
                maker,
                maker_bytes: mbytes.clone(),
                payout_note: vec![0u8; 1153],
                membership_carrier: Vec::new(),
                membership_tip: Vec::new(),
                payout_clue: Vec::new(), // `.level()` reads the terms only
            }
            .level()
        );
        let (ca, ja) = route(&node_a, "POST", "/book_level", &level_body);
        let (cb, jb) = route(&node_b, "POST", "/book_level", &level_body);
        assert_eq!((ca, cb), (200, 200), "both nodes answer");
        let slots = format!("\"slots\":{}", crate::order_book::LEVEL_SLOTS);
        assert!(ja.contains(&slots), "A serves the constant slot count: {ja}");
        assert!(jb.contains(&slots), "B serves the SAME constant slot count: {jb}");
        assert!(
            ja.contains(&hex_encode(&mbytes)),
            "A must serve the order's maker bytes — a taker cannot fill what it cannot read"
        );

        // ⛔ AN OUT-OF-RANGE LEVEL IS REFUSED, never wrapped onto a real level (which would show a taker
        // orders that do not rest where they are looking).
        let oob = format!(
            "{{\"asset_a\":\"{}\",\"asset_b\":\"{}\",\"level\":{}}}",
            h3(&t.asset_a),
            h3(&t.asset_b),
            crate::order_book::LATTICE_LEVELS
        );
        let (oc, _) = route(&node_a, "POST", "/book_level", &oob);
        assert_eq!(oc, 400, "a level off the grid must be refused");
    }

    /// ⭐ DB-334 — A REPORTED DOUBLE-SIGN TRAVELS TO A PEER THAT WAS NEVER TOLD, AND EVERY MALFORMED REPORT IS REFUSED.
    ///
    /// TWO-PARTY: two independent runtimes on one genesis, joined only by a loopback pair. The pair is reported to A's
    /// route; B, never told, must hold the evidence in its OWN pool — the observed effect. A block carrying it would SETTLE
    /// it on B, never pool it, so B's pool holding it can only be A's gossip (DB-335's marking door). RED before DB-334:
    /// the route did not exist.
    /// The votes are two finality votes by one fresh ML-DSA-65 key at one height naming two blocks: the object needs no
    /// held block and no bonded voter to be well-formed (the graft door decides the slash from chain state; the
    /// `db266_…` pins and the real two-process pin carry that half). TAMPER: a flipped signature, two keys, two heights
    /// and one block twice are REFUSED at A's door and reach NEITHER pool; an undecodable vote is BAD_VOTES.
    #[test]
    fn db334_a_reported_equivocation_travels_to_a_peer_and_every_malformed_report_is_refused() {
        let g = crate::node::tests::genesis_block();
        let (ta, tb) = LoopbackTransport::pair();
        let a = Arc::new(Mutex::new(NodeRuntime::new(Node::new(g.clone()).unwrap(), ta)));
        let mut b = NodeRuntime::new(Node::new(g).unwrap(), tb);
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let (pk2, sk2) = crate::pqauth::ml_dsa_keypair();
        let vote = |pk: &[u8], sk: &[u8], tag: &[u8], height: u64| {
            let block = Hash32::hash(tag);
            crate::validator::VoteCert {
                pubkey: pk.to_vec(),
                block,
                height,
                sig: crate::pqauth::ml_dsa_sign(&crate::pqauth::finality_vote_msg(&block, height), sk).expect("sign"),
            }
        };
        let body = |x: &crate::validator::VoteCert, y: &crate::validator::VoteCert| {
            format!(r#"{{"vote_a_hex":"{}","vote_b_hex":"{}"}}"#, hex_encode(&x.to_wire()), hex_encode(&y.to_wire()))
        };
        let id_of = |x: &crate::validator::VoteCert, y: &crate::validator::VoteCert| {
            crate::equivocation_tx::wire(x, y).map(|blob| crate::mempool::PqTx::content_id(&blob))
        };
        let in_a = |id: Option<Hash32>| {
            id.is_some_and(|id| a.lock().unwrap_or_else(|e| e.into_inner()).node().mempool().contains(&id))
        };
        let (x, y) = (vote(&pk, &sk, b"db334-x", 9), vote(&pk, &sk, b"db334-y", 9));
        let mut flipped = y.clone();
        flipped.sig[7] ^= 1;
        let two_keys = vote(&pk2, &sk2, b"db334-y", 9);
        let two_heights = vote(&pk, &sk, b"db334-y", 10);
        let tampers = [
            ("a flipped signature", &x, &flipped),
            ("two keys", &x, &two_keys),
            ("two heights", &x, &two_heights),
            ("one block twice", &x, &x),
        ];
        // TAMPERS first, so an honest pooled pair can never mask a refusal.
        for (name, p, q) in tampers {
            let (code, reply) = route(&a, "POST", "/report_equivocation", &body(p, q));
            assert!(code != 200 && reply.contains("REFUSED"), "TAMPER ({name}) must be REFUSED: {code} {reply}");
            assert!(!in_a(id_of(p, q)), "TAMPER ({name}) pooled an object on A");
        }
        let (code, reply) = route(&a, "POST", "/report_equivocation", r#"{"vote_a_hex":"00","vote_b_hex":"00"}"#);
        assert!(reply.contains("BAD_VOTES"), "an undecodable vote must be BAD_VOTES: {code} {reply}");
        let (code, reply) = route(&a, "POST", "/report_equivocation", &body(&x, &y));
        assert_eq!(code, 200, "the honest report: {reply}");
        assert!(reply.contains("PUBLISHED"), "the honest report must be PUBLISHED: {reply}");
        let id = id_of(&x, &y).expect("one key, one height, two blocks");
        assert_eq!(id_of(&y, &x), Some(id), "CONTROL: the reversed pair names the same canonical object");
        assert!(in_a(Some(id)), "CONTROL: A's own pool holds the evidence it was told of");
        assert!(!b.node().mempool().contains(&id), "PRECONDITION: B does not hold it before any tick");
        let (fr, mc) = (Hash32::hash(b"db334-fr"), Hash32::hash(b"db334-mc"));
        let t0 = {
            let g = a.lock().unwrap_or_else(|e| e.into_inner());
            g.node().dag().get(&g.node().selected_tip().expect("tip")).expect("header").header.timestamp + 60_000
        };
        let mut ticks = 0u64;
        // ⭐ THE WITNESS IS B'S GOSSIP DOOR (cycle 16, F2, MEASURED): the two runtimes join each other on the first beacon
        // and produce, so a block can carry the evidence in the tick it arrives — F2 showed it assembled on B twice and
        // carried by a block while a between-tick pool check saw nothing. `txs_ingested` counts only gossip admissions,
        // and A has pooled exactly ONE object (the reported evidence), so a non-zero count on B is that evidence
        // reaching B — never told — without a block.
        assert_eq!(
            a.lock().unwrap_or_else(|e| e.into_inner()).node().mempool().len(),
            1,
            "PRECONDITION: A pooled exactly the reported evidence, so B's gossip count is it"
        );
        let mut gossiped = 0usize;
        while ticks < 400 && gossiped == 0 {
            let now = t0 + ticks * crate::net::COVER_INTERVAL_MS;
            let _ = a.lock().unwrap_or_else(|e| e.into_inner()).tick(now, fr, mc);
            gossiped += b.tick(now, fr, mc).txs_ingested;
            ticks += 1;
        }
        assert!(
            gossiped > 0,
            "⛔ DB-334: after {ticks} tick(s) B — never told — admitted nothing through its gossip door: the evidence \
             reported to A never travelled"
        );
        for (name, p, q) in tampers {
            assert!(
                id_of(p, q).is_none_or(|t| !b.node().mempool().contains(&t)),
                "TAMPER ({name}) reached the peer's pool"
            );
        }
    }

    /// ⛔⛔ DB-332 — EACH NODE SERVES ITS OWN OLI INDEX, NEVER ANOTHER NODE'S.
    ///
    /// The serve index was process-global (`static CACHE` in `oli_index`, keyed only by the epoch end), so a second
    /// runtime in the same process was handed the FIRST runtime's index whenever their epoch ends matched — measured as
    /// the late-clue route pin passing alone and failing ("Found []") beside another OLI pin on the same binary. RED
    /// before DB-332: B's first ask returned A's `Arc` outright. TWO-PARTY-REVIEWED: two independent runtimes.
    #[test]
    fn db332_each_node_serves_its_own_oli_index_never_another_nodes() {
        let a = fresh();
        let b = fresh();
        let served = |rt: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>| -> Arc<crate::oli::Index> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            loop {
                if let Some(idx) = oli_index(&rt.lock().unwrap_or_else(|e| e.into_inner())) {
                    return idx;
                }
                assert!(std::time::Instant::now() < deadline, "the node's own OLI index never landed");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        let ia = served(&a);
        let ib = served(&b);
        assert!(
            !Arc::ptr_eq(&ia, &ib),
            "⛔ DB-332: node B was served node A's OLI index — a process-global cache keyed only by the epoch end, so \
             every runtime in the process reads whichever node built first"
        );
        assert!(Arc::ptr_eq(&ia, &served(&a)), "CONTROL: a node's own index is cached for it (built once per epoch)");
    }

    /// ⛔ DB-408 PIN — A NODE THAT HOLDS NO OLI INDEX YET (a fresh process: every restart) ANSWERS ITS FIRST ASK, NEVER
    /// 503 "ask again". MEASURED sim-20261007-020907 (T3): the first `/oli_params` after node 0's restart answered 503
    /// `BUILDING` while the build that ask had started took 0 ms; the wallet's change-index sweep refused the unbond
    /// ("the change index cannot be derived from the chain yet … status code 503 — nothing was sent"). Asked here through
    /// the PRODUCTION router, exactly once per route, on a node whose serve cache is empty. RED before DB-408: the first
    /// `/oli_params` answered 503 (`oli_index` returned before the build it had spawned could land).
    /// ROOT-LAYER: `oli_index_ready` is the one read all four OLI routes make; this pin asks two of them cold.
    /// MEASURED: before → 503 on the first ask (sim-20261007-020907, and this pin on the preDB408 tree); after → 200.
    /// MUST-STAY-GREEN: db332 (each node serves its own index — the cache cell is still per node).
    /// TWO-PARTY-REVIEWED: the answers are the node's own serving shape (a fresh runtime is the restarted process).
    #[test]
    fn db408_a_node_with_no_oli_index_yet_answers_its_first_ask() {
        let a = fresh();
        let empty = |rt: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>| {
            let cell = rt.lock().unwrap_or_else(|e| e.into_inner()).node().oli_serve_cache();
            let g = cell.state.lock().unwrap_or_else(|e| e.into_inner());
            g.built.is_none() && g.building.is_none()
        };
        assert!(empty(&a), "CALIBRATION: a fresh process holds no OLI index and no build");
        let (code, params) = route(&a, "POST", "/oli_params", "{}");
        assert_eq!(code, 200, "⛔ DB-408: the first /oli_params of a node with no index yet was not answered: {params}");
        assert!(params.contains("\"shard_bits\""), "the answer carries the index shape: {params}");
        // The same on a second fresh node for the table route (the other read a wallet's first send makes).
        let b = fresh();
        assert!(empty(&b), "CALIBRATION: the second fresh process holds no OLI index either");
        let (tcode, table) = route(&b, "POST", "/oli_table", "{\"shard\":0}");
        assert_eq!(tcode, 200, "⛔ DB-408: the first /oli_table of a node with no index yet was not answered: {}", &table[..table.len().min(200)]);
        assert!(table.contains("\"table_hex\""), "the answer is one whole table");
    }

    #[test]
    fn get_nf_unspent_acc_route_serves_the_live_a_tip() {
        use usdm_decider::nf_sparse_air::{nf_to_limbs, sparse_fold_digest_nfs};
        let rt = fresh();
        // genesis: the route serves the DERIVED A_tip seed. It is deliberately NOT all-zero — the seed is
        // network-derived (a testnet A_tip can never equal a mainnet one at the same block set) and all-zero
        // is this codebase's "unset" sentinel, which a live consensus value must never collide with.
        // Asserted against the one definition, `Node::nf_unspent_acc_genesis()`, never a copied literal.
        // A_tip travels in its canonical 32-byte form (`leaf_to_cm_bytes`) — asserted through the one
        // encoder, never a re-typed lane walk (which is what §AG class 9 was: this very test laid eight
        // lanes into a literal `[0u8; 32]` and panicked before the route did).
        let genesis_hex = hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(
            crate::node::Node::nf_unspent_acc_genesis(),
        ));
        let (code, json) = route(&rt, "GET", "/get_nf_unspent_acc", "");
        assert_eq!(code, 200);
        assert!(
            json.contains(&format!("\"a_tip_hex\":\"{genesis_hex}\"")),
            "genesis A_tip is the derived seed; got {json}"
        );
        assert!(
            json.contains("\"blocks\":0"),
            "no blocks folded yet; got {json}"
        );
        // advance A_tip over 3 folds, then the route must serve the ADVANCED value byte-for-byte.
        let expect_hex = {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let node = g.node_mut();
            for h in 0..3u64 {
                let tags = crate::cover::nullifier_wire_fill(
                    &[],
                    &crate::cover::nullifier_block_secret(b"rpc-test-blobs", &[0u8; 32]),
                );
                let mut pb = [0u8; 32];
                pb[0] = 0xE0u8.wrapping_add(h as u8);
                let pre = nf_to_limbs(&pb);
                let digest = sparse_fold_digest_nfs(&tags, pre);
                node.advance_nf_unspent_acc(pre, digest);
            }
            hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(node.nf_unspent_acc()))
        };
        let (code, json) = route(&rt, "GET", "/get_nf_unspent_acc", "");
        assert_eq!(code, 200);
        assert!(
            json.contains(&format!("\"a_tip_hex\":\"{expect_hex}\"")),
            "route serves the LIVE advanced A_tip; expected {expect_hex} in {json}"
        );
        assert_ne!(
            expect_hex,
            "0".repeat(64),
            "A_tip actually advanced off the zero seed"
        );
    }

    // DIGITAL-CASH PRIVACY (absence, adversarial): a chain observer querying ANY node RPC must be unable to
    // total the DAG's value — its locked reserve, its aggregate stake, or its transaction throughput. Every
    // value-AGGREGATE field is FORBIDDEN from every served response; a regression that re-adds one (a
    // convenience stat, an explorer number) would let anyone sum the money the whole private DAG holds. This
    // test fails the instant any such aggregate reappears on the wire. (Policy CONSTANTS like ratios/lock
    // periods are allowed; per-self lookups like /get_validator_bond are allowed — neither exposes a total.)
    #[test]
    fn served_rpc_leaks_no_value_aggregate() {
        let rt = fresh();
        // Field names that would each disclose a global value aggregate — must be ABSENT from every response.
        let forbidden = [
            "bridge_tvl",          // locked-reserve aggregate
            "validator_total",     // aggregate stake
            "total_bond",          // aggregate stake
            "required_bond_floor", // = 2×bridge_tvl (discloses the reserve aggregate)
            "minted_usdm",         // peg-issued running total
            "reserve_value",       // reserve aggregate
            "mempool_txs",         // pending-tx COUNT (throughput)
            "mempool_weight",      // pending-tx VOLUME (throughput)
        ];
        for (m, path) in [
            ("GET", "/get_info"),
            ("GET", "/get_governance"),
            ("GET", "/get_validator_bond_tree"),
            ("GET", "/get_delegation_targets"),
        ] {
            let (code, json) = route(&rt, m, path, "");
            assert_eq!(code, 200, "{path} should serve OK");
            for f in forbidden {
                assert!(
                    !json.contains(&format!("\"{f}\"")),
                    "{path} SERVED a value-aggregate field \"{f}\" — a private DAG must leak zero value totals: {json}"
                );
            }
        }
    }

    #[test]
    fn two_independent_nodes_both_refuse_a_spend_that_proves_no_membership() {
        // THE MANDATE, MEASURED AT THE ADMISSION GATE — I previously asserted it from code reading, and said
        // so. This is the measurement. It must live HERE: the send tests drive `ingest_tx_unverified`, which
        // bypasses this gate, so they can never exercise it. Driven through the REAL `route()` dispatcher.
        //
        // TWO INDEPENDENT NODES: `a` and `b` are separate runtimes with separate state, sharing nothing, and
        // every assertion demands the IDENTICAL verdict from both. A verdict only one node reaches is not a
        // rule — it is that node's opinion, and a spender would simply resubmit to the other. Consensus rules
        // must be derived identically by strangers.
        let a = fresh();
        let b = fresh();

        // 1. A tx that reveals a nullifier, with NO membership evidence ⇒ REFUSED by BOTH, fail-closed.
        //    The recursive membership fold is the only evidence accepted, and it is the one with no capacity
        //    ceiling (MEASURED in `capacity_free_membership_proof`: no chain-length term, constant ~9.3 KB).
        let spend = format!(
            "{{\"tx_as_hex\":\"{}\",\"nullifiers_hex\":\"{}\"}}",
            hex_encode(&vec![9u8; 96]),
            hex_encode(&[0x42u8; 32]),
        );
        for (who, rt) in [("A", &a), ("B", &b)] {
            let (code, json) = route(rt, "POST", "/submit_pq_tx", &spend);
            assert_eq!(
                code, 200,
                "node {who}: a refusal is a normal answer, not a transport error; got {json}"
            );
            assert!(
                json.contains("MEMBERSHIP_PROOF_MISSING"),
                "node {who}: a spend with no membership evidence MUST be refused; got {json}"
            );
        }

        // 2. A tx revealing NO nullifier is untouched on BOTH — it has no note to prove. The gate binds
        //    spends only, so it fails closed on the bad ITEM while chain progress continues.
        let non_spend = format!("{{\"tx_as_hex\":\"{}\"}}", hex_encode(&vec![9u8; 96]));
        for (who, rt) in [("A", &a), ("B", &b)] {
            let (_, json_ns) = route(rt, "POST", "/submit_pq_tx", &non_spend);
            assert!(
                !json_ns.contains("MEMBERSHIP_PROOF_MISSING"),
                "node {who}: a tx with no nullifier must not be caught by the spend mandate; got {json_ns}"
            );
            let (_, info) = route(rt, "GET", "/get_info", "");
            assert!(
                info.contains("\"status\":\"OK\""),
                "node {who} still serves after a refusal; got {info}"
            );
        }

        // ⛔⛔⛔ THE ZERO-COMMIT HOLE, CLOSED AND PROVEN. A BOND/STAKE reveals a nullifier, and its verify is
        // now cross-bound: it passes `Some(cm_bytes_to_leaf(tx.membership_leaf_commit))`, which DROPS the
        // Merkle weld. If that field were absent it would be ALL-ZERO — the carrier would bind a placeholder
        // while the weld was already gone, leaving membership proven by NOTHING. That is exactly the hole gate
        // D's own doc names: it is "only sound because the NODE refuses a tx that carries the cross-bind
        // without a VERIFIED membership carrier".
        // It is closed because the mandate above refuses ANY nullifier-bearing tx without a verified carrier,
        // and that refusal RETURNS before the bond/stake verify is reached. Asserted here rather than left to
        // a reader tracing statement order — order-dependent safety is the kind that silently breaks.
        let bond_no_carrier = format!(
            "{{\"tx_as_hex\":\"{}\",\"nullifiers_hex\":\"{}\",\"bond_notes_hex\":\"{}\"}}",
            hex_encode(&vec![9u8; 96]),
            hex_encode(&[0x42u8; 32]),
            hex_encode(&vec![0u8; 40]),
        );
        // The door's EARLIEST refusal for a bond names exactly that, before any cross-bound verify could be handed an all-zero
        // commitment — asserted by its variant, never by a bare "refused". DECLARED AMENDMENT (2026-10-07, VALIDATOR BONDS ARE
        // SAT-ONLY): the earliest refusal is now the intake's `USDM_BOND_RETIRED`, keyed on `bond_notes_hex` before ANY proof
        // (it was `MEMBERSHIP_PROOF_MISSING`); the bond verify the zero-commit hole concerned no longer exists at this door.
        let earliest = "USDM_BOND_RETIRED";
        for (who, rt) in [("A", &a), ("B", &b)] {
            let (_, json_b) = route(rt, "POST", "/submit_pq_tx", &bond_no_carrier);
            assert!(
                json_b.contains(earliest),
                "node {who}: a BOND with a nullifier and NO membership carrier MUST be refused ({earliest}) before its \
                 cross-bound verify can be handed an all-zero commitment; got {json_b}"
            );
            assert!(rt.lock().unwrap().node().mempool().is_empty(), "node {who}: ⛔ a refused bond was pooled");
        }
    }

    #[test]
    fn submit_bad_hex_is_rejected_not_a_panic() {
        let rt = fresh();
        let (code, json) = route(
            &rt,
            "POST",
            "/submit_pq_tx",
            "{\"tx_as_hex\":\"zz\",\"do_not_relay\":false}",
        );
        assert_eq!(code, 200);
        assert!(json.contains("REJECTED"), "got {json}");
    }

    #[test]
    fn submit_missing_field_is_rejected() {
        let rt = fresh();
        let (code, json) = route(&rt, "POST", "/submit_pq_tx", "{\"do_not_relay\":false}");
        assert_eq!(code, 200);
        assert!(json.contains("MISSING_TX_AS_HEX"), "got {json}");
    }

    #[test]
    fn json_str_field_decodes_escapes_to_the_signed_bytes() {
        // The profile topic packs `bio \u{1f} fee` — the wallet signs the TRUE bytes and serde_json encodes
        // the control char as \u001f on the wire. The node must decode back to the identical bytes or the
        // signature check refuses an honest sign-up (the 2026-08-24 live failure).
        let body = "{\"topic\":\"bio\\u001f2000000\",\"name\":\"a\\\\b\\\"c\\n\"}";
        assert_eq!(
            super::json_str_field(body, "topic").as_deref(),
            Some("bio\u{1f}2000000"),
            "\\uXXXX must decode to the control char the wallet signed"
        );
        assert_eq!(super::json_str_field(body, "name").as_deref(), Some("a\\b\"c\n"));
    }

    #[test]
    fn json_str_field_extracts_hex() {
        assert_eq!(
            json_str_field(
                "{\"tx_as_hex\":\"deadBEEF\",\"do_not_relay\":true}",
                "tx_as_hex"
            )
            .as_deref(),
            Some("deadBEEF")
        );
    }

    #[test]
    fn json_num_field_extracts_stamp() {
        assert_eq!(
            json_num_field("{\"tx_as_hex\":\"aa\",\"pow_stamp\":4213}", "pow_stamp"),
            Some(4213)
        );
    }

    #[test]
    fn unknown_route_404() {
        let rt = fresh();
        let (code, _) = route(&rt, "GET", "/nope", "");
        assert_eq!(code, 404);
    }

    /// ⛔⛔⛔ A PEG-IN CANNOT CREDIT A NOTE THE CALLER SIZED FOR ITSELF.
    ///
    /// The threshold attestation binds `(deposit_id, new_reserve_commit, new_minted_commit, recipient)`
    /// — it never names the note, and a node cannot read a sealed note's amount. So the ONLY thing
    /// standing between "authorized 100" and "credited 1,000,000" is the mint carrier welding the
    /// recorded commitment to the authorized value. MEASURED 2026-08-26: `verify_mint_validity` had
    /// ZERO call sites in node.rs/peg.rs/rpc_http.rs while the primitive sat unused at
    /// whir_rec_block.rs:10673, and this path ended in a bare `record_note_payload`.
    ///
    /// Two parties by construction: the CLAIMANT builds a note + carrier and hands over only bytes; the
    /// NODE holds no secret and must decide from those bytes alone.
    #[test]
    fn a_peg_in_note_whose_commitment_does_not_open_to_the_authorized_mint_is_refused() {
        use usdm_decider::whir_rec_block::{prove_mint_validity_bytes, verify_mint_validity_bytes};

        const AUTHORIZED: u64 = 100;
        const GREEDY: u64 = 1_000_000;
        let sk = usdm_decider::poseidon2_compress::lanes_of(&[7, 8, 9, 10]);

        // The CLAIMANT seals a note for the amount it was authorized, and proves it.
        let (honest_carrier, honest_cm) =
            prove_mint_validity_bytes(AUTHORIZED, &sk).expect("an honest claim proves");
        // The NODE's view: the note bytes it would record, and the cm it recovers from them.
        let mut honest_note = vec![0u8; 1153];
        honest_note[..crate::spend_frontier::NOTE_CM_BYTES]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(honest_cm));
        let recovered = crate::spend_frontier::note_cm_of(&honest_note)
            .expect("a note in the production layout opens to its commitment");
        assert_eq!(
            recovered, honest_cm,
            "the node must recover exactly the cm the carrier welds — `leaf_to_cm_bytes` at the note's \
             front and `note_cm_of` reading it are the ONE contract every producer and door share"
        );
        assert!(
            verify_mint_validity_bytes(&honest_carrier, recovered, AUTHORIZED),
            "an honest credit still lands"
        );

        // ⛔ THE ATTACK: the claimant seals for far more than it was authorized. Its carrier is perfectly
        // valid — for the GREEDY amount — so the forgery is not in the proof, it is in the mismatch.
        let (greedy_carrier, greedy_cm) =
            prove_mint_validity_bytes(GREEDY, &sk).expect("the greedy note also proves — for its own value");
        assert_ne!(greedy_cm, honest_cm, "a different amount is a different commitment");
        assert!(
            !verify_mint_validity_bytes(&greedy_carrier, greedy_cm, AUTHORIZED),
            "a note sealed for {GREEDY} must NOT verify against an authorized {AUTHORIZED} — this is \
             the inflation hole: the caller does not get to choose what it receives"
        );
        // And the mirrored attempt — the greedy note with the honest carrier — is refused too.
        assert!(
            !verify_mint_validity_bytes(&honest_carrier, greedy_cm, AUTHORIZED),
            "an honest carrier cannot be re-pointed at a bigger note"
        );
        // A missing carrier is a refusal, never a credit.
        assert!(
            !verify_mint_validity_bytes(&[], recovered, AUTHORIZED),
            "no carrier ⇒ no credit"
        );
    }

    #[test]
    fn wrapped_mint_execute_route_full_stack_and_gates() {
        // HTTP-LAYER e2e for the IonSwap wrapped mint — drives the REAL /register_wrapped_asset + /wrapped_mint_execute
        // JSON routes through the dispatch, proving parse → orchestrate-from-sealed-opening → deposit-confirmation gate
        // → ≥2/3 custodian threshold → note record → JSON outcome. Complements the node-level money-path test with the
        // wire layer + its gates (BAD_FIELDS, the owner gate, the request lane, ALREADY_MINTED).
        let rt = fresh();
        let hx = |b: u8, n: usize| -> String {
            std::iter::repeat(format!("{:02x}", b)).take(n).collect()
        };

        // ⛔⛔⛔ GOVERNANCE REGISTER IS NO LONGER A LOCAL MUTATION (2026-09-11). `/register_wrapped_asset`
        // used to set the ratio directly in this node's ledger, so a socket decided a CONSENSUS value and
        // every other node derived a different one from blocks. The route now PUBLISHES a
        // `Class::WrappedAssetRegister` object and the ratio is set only by the >=2/3-attested door at
        // apply, on every node. This test therefore drives BOTH halves: the publisher over HTTP, and the
        // apply that actually registers.
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        {
            // The bonded quorum has to exist BEFORE a registration can apply — `threshold_ok` is
            // `total > 0 && ...`, so with no bonded weight nothing registers. That is the correct
            // fail-closed posture, and it is why the bond moved above the register in this test.
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut()
                .admit_validator(crate::pqauth::pubkey_id(&pk), 20_000, 0)
                .unwrap();
        }

        // The attestation wire the threshold routes share: pubkey_len(u16 LE) ‖ pubkey ‖ sig_len ‖ sig.
        let att_hex = |asset_id: u32, prev: u32, ratio: u32| -> String {
            let msg = crate::peg::PegLedger::wrapped_register_msg(1, asset_id, prev, ratio);
            let sig = crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the bonded validator signs");
            let mut b: Vec<u8> = Vec::new();
            b.extend_from_slice(&(pk.len() as u16).to_le_bytes());
            b.extend_from_slice(&pk);
            b.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            b.extend_from_slice(&sig);
            hex_encode(&b)
        };

        // THE PUBLISHER, over the real HTTP dispatch: the route emits an object the node ADMITS. An
        // UNATTESTED registration is not an object at all, so the route cannot publish one — proven first
        // so the success below is not mistaken for the route accepting anything it is handed.
        let (_c, ju) = route(
            &rt,
            "POST",
            "/register_wrapped_asset",
            "{\"asset_id\":7,\"ratio_bps\":15000,\"epoch_id\":1}",
        );
        assert!(
            ju.contains("PUBLISH_REFUSED"),
            "an unattested registration must not be publishable: {ju}"
        );

        let (code, j) = route(
            &rt,
            "POST",
            "/register_wrapped_asset",
            &format!(
                "{{\"asset_id\":7,\"ratio_bps\":15000,\"epoch_id\":1,\"attestors_hex\":\"{}\"}}",
                att_hex(7, 0, 15_000)
            ),
        );
        assert_eq!(code, 200);
        assert!(j.contains("PUBLISHED"), "the route publishes the registration object: {j}");

        // THE APPLY, through the real block-apply seam: >=2/3 of the bonded weight attests the exact
        // transition 0 -> 15000, and only then does the ledger hold the ratio.
        {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let h = crate::wrapped_asset_tx::WrappedAssetRegisterHeader {
                epoch_id: 1,
                asset_id: 7,
                prev_ratio_bps: 0,
                ratio_bps: 15_000,
            };
            let msg = crate::peg::PegLedger::wrapped_register_msg(
                h.epoch_id,
                h.asset_id,
                h.prev_ratio_bps,
                h.ratio_bps,
            );
            let att = vec![crate::psm::MintAttestor {
                pubkey: pk.clone(),
                sig: crate::pqauth::ml_dsa_sign(&msg, &sk).expect("the bonded validator signs"),
            }];
            let blob = crate::wrapped_asset_tx::wire(&h, &att);
            assert_eq!(
                crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register(
                    g.node_mut(),
                    &blob,
                    &crate::pqauth::MlDsaVerifier,
                ),
                crate::wrapped_asset_tx::RegisterApply::Registered,
                "the attested registration must apply"
            );
            assert_eq!(
                g.node().peg().wrapped_asset_ratio_bps(7),
                Some(15_000),
                "the ratio is set by the CHAIN object, not by the socket"
            );
        }

        // A SUB-1:1 REGISTRATION IS NOW REFUSED AT THE WIRE, not silently clamped: an attestation
        // authorises an exact transition, and clamping would apply a ratio nobody signed. The publisher
        // therefore cannot get one admitted at all.
        // NON-VACUITY: this one IS properly attested, so the only thing left to refuse it is the ratio.
        let (_c, jc) = route(
            &rt,
            "POST",
            "/register_wrapped_asset",
            &format!(
                "{{\"asset_id\":2,\"ratio_bps\":5000,\"epoch_id\":1,\"attestors_hex\":\"{}\"}}",
                att_hex(2, 0, 5_000)
            ),
        );
        assert!(
            jc.contains("PUBLISH_REFUSED"),
            "a sub-1:1 registration must be refused ON ITS RATIO, never clamped: {jc}"
        );
        {
            let g = rt.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                g.node().peg().wrapped_asset_ratio_bps(2),
                None,
                "a refused registration must leave the asset unregistered — never clamped into existence"
            );
        }

        // Missing asset_id → BAD_FIELDS (route-level validation, no panic).
        let (_c, jb) = route(
            &rt,
            "POST",
            "/wrapped_mint_execute",
            "{\"deposit_id\":\"aa\"}",
        );
        assert!(jb.contains("BAD_FIELDS"), "got {jb}");

        let addr_s = crate::btc_tx::address_for_test_seed(crate::bridge::btc_hrp(), b"wrap-route");
        let addr = addr_s.as_str();
        // A real mint request NAMES ITS OWNER. The credit gate refuses without it — a minted note filed in no
        // account bucket is undiscoverable money, findable only by walking the whole note stream.
        // ⛔ THE CREDIT IS GATED ON A PROOF now: the note's commitment must open to the AUTHORIZED
        // amount IN THIS ASSET. A fabricated 48-zero payload — what this test used to post — is exactly
        // what the gate exists to refuse, so the request carries a real note and its carrier. The tag
        // comes from `wrapped_asset_tag_u32`, the same derivation the node uses.
        let note_sk = usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]);
        let wtag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(7);
        // DB-80b: the amount rides COMMITTED — the requester's blind, its commitment, the committed carrier
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x80, 0xb, 0x2]);
        let (wcarrier, wcm, wdc) =
            usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(2000, wtag, &note_sk, &wdb)
                .expect("an authorized amount proves its own commitment in its own asset");
        let mut wnote = vec![0u8; 1153];
        wnote[..crate::spend_frontier::NOTE_CM_BYTES]
            .copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(wcm));
        let wnote_hex = hex_encode(&wnote);
        let wcarrier_hex = hex_encode(&wcarrier);
        let wdelta_hex = hex_encode(&crate::spend_frontier::leaf_to_cm_bytes(wdc));
        let wdb_hex = hex_encode(&crate::spend_frontier::digest_to_lane_bytes(&wdb));
        // DB-273 §19 L1: the owner is the credited note's OLI clue (the door computes the recipient that commits to it).
        let owner_clue = vec![0xC5u8; crate::peg_in_tx::OWNER_CLUE_MAX];
        let body_ok = format!(
            "{{\"asset_id\":7,\"deposit_id\":\"{}\",\"deposit_value\":3000,\"mint\":2000,\"delta_commit\":\"{}\",\"d_blind_hex\":\"{}\",\"note_payload\":\"{}\",\"mint_carrier_hex\":\"{}\",\"reserve_address\":\"{}\",\"note_clue_hex\":\"{}\"}}",
            hex_encode(&crate::peg::deposit_id_for_reserve_address(addr)), wdelta_hex, wdb_hex, wnote_hex, wcarrier_hex, addr,
            hex_encode(&owner_clue)
        );

        // AND THE GATE ITSELF: the same request WITHOUT an owner must be refused, or the requirement is
        // decorative and a forgotten caller silently mints money nobody can find.
        // DB-93: one deposit per address, so the owner-gate probe is its OWN deposit (a second funded
        // address) — the first address's deposit is minted by then and would answer ALREADY_MINTED.
        let addr2_s = crate::btc_tx::address_for_test_seed(crate::bridge::btc_hrp(), b"wrap-route-2");
        let addr2 = addr2_s.as_str();
        crate::btc_watch::inject_confirmed_for_test(addr2, 1_000_000);
        let body_no_owner = format!(
            "{{\"asset_id\":7,\"deposit_id\":\"{}\",\"deposit_value\":3000,\"mint\":2000,\"delta_commit\":\"{}\",\"d_blind_hex\":\"{}\",\"note_payload\":\"{}\",\"mint_carrier_hex\":\"{}\",\"reserve_address\":\"{}\"}}",
            hex_encode(&crate::peg::deposit_id_for_reserve_address(addr2)), wdelta_hex, wdb_hex, wnote_hex, wcarrier_hex, addr2
        );

        // ⭐ DB-77 — THE DOOR IS A REQUEST ON ANY NODE. The bonded custodian's KEM ek is what a requester seals
        // the amounts / reserve address / owner keys to; register it (the chain path is the membership bond).
        let (kem_ek, kem_dk) = crate::pqkem::keypair();
        {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.node_mut().register_custody_kem(crate::pqauth::pubkey_id(&pk), kem_ek.clone());
        }
        // A node with NO bridge signer (not a custodian) is no longer refused: it REQUESTS, and the request
        // is sealed to the bonded set. (A different deposit id: this request's slot stays open here because a
        // single in-process runtime has nobody to gossip it to.)
        let body_other = format!(
            "{{\"asset_id\":7,\"deposit_id\":\"{}\",\"deposit_value\":3000,\"mint\":2000,\"delta_commit\":\"{}\",\"d_blind_hex\":\"{}\",\"note_payload\":\"{}\",\"mint_carrier_hex\":\"{}\",\"reserve_address\":\"{}\",\"note_clue_hex\":\"{}\"}}",
            hex_encode(&crate::peg::deposit_id_for_reserve_address(addr)), wdelta_hex, wdb_hex, wnote_hex, wcarrier_hex, addr,
            hex_encode(&owner_clue)
        );
        let (_c, jn) = route(&rt, "POST", "/wrapped_mint_execute", &body_other);
        assert!(
            jn.contains("REQUESTED") && jn.contains("\"minted\":false") && !jn.contains("NOT_A_CUSTODIAN"),
            "DB-77: a non-custodian node must REQUEST, never refuse: {jn}"
        );

        // Configure THIS node as the custodian (1-of-1 quorum): the bridge signer + the KEM identity + a
        // CONFIRMED foreign deposit at the reserve address (the confirmation the live watcher would read).
        {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.set_bridge_signer(pk.clone(), sk.clone());
            g.set_custody_kem(kem_ek.clone(), kem_dk.clone());
        }
        crate::btc_watch::inject_confirmed_for_test(addr, 1_000_000);
        let (code, jm) = route(&rt, "POST", "/wrapped_mint_execute", &body_ok);
        assert_eq!(code, 200);
        // DB-93: the deposit id is the function of the address, so this is the SAME request the
        // non-custodian door already recorded — the door answers GATHERING (the slot exists; the
        // custodian acts on it) rather than REQUESTED. Either way nothing is minted at the door.
        assert!(
            (jm.contains("REQUESTED") || jm.contains("GATHERING")) && jm.contains("\"gathering\":true") && !jm.contains("\"minted\":true"),
            "the door requests; nothing is minted at the door any more (DB-77): {jm}"
        );
        assert!(jm.contains("\"asset_id\":7"), "got {jm}");
        // The lane completes in the runtime tick: the custodian proposed at the door (own opening), its own
        // signature meets the 1-of-1 threshold, so the tick PUBLISHES the `Class::WrappedMint` object.
        let key = crate::peg_attest::slot_key_for(7, &crate::peg::deposit_id_for_reserve_address(addr));
        {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            g.peg_lane_tick(crate::node_runtime::unix_ms_now() + 20_000);
            assert!(
                g.node().wrapped_mint_is_published(&key),
                "the tick must publish the completed wrapped mint (the ONE prove) — nothing else does"
            );
            assert!(
                !g.node().peg().wrapped_deposit_minted(1, &crate::peg::deposit_id_for_reserve_address(addr)),
                "⛔ the ledger moved at PUBLISH — that is the §DA local mutation DB-77 removes; only a block may move it"
            );
        }
        let (_c, jp) = route(&rt, "POST", "/wrapped_mint_execute", &body_ok);
        assert!(
            jp.contains("CONFIDENTIAL_PUBLISHED") && jp.contains("\"published\":true"),
            "a poll before the block answers published: {jp}"
        );
        // A block carries it; the producer runs the object seam for its OWN block (§DA) → minted here.
        {
            let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
            let b = g
                .node_mut()
                .produce(4_500, crate::hash::Hash32::hash(b"fr"), crate::hash::Hash32::hash(b"mc"))
                .expect("the block carrying the wrapped mint");
            assert!(
                g.node().peg().wrapped_deposit_minted(7, &crate::peg::deposit_id_for_reserve_address(addr)),
                "the block's wrapped mint applied on its producer (block {:?})",
                b.id()
            );
            assert!(
                g.node().holds_record_with_cm(&crate::spend_frontier::leaf_to_cm_bytes(wcm)),
                "⛔⛔⛔ FUND SAFETY: the wrapped note is not held after the block that carries it applied"
            );
        }
        let (_c, jminted) = route(&rt, "POST", "/wrapped_mint_execute", &body_ok);
        assert!(
            jminted.contains("\"minted\":true") && jminted.contains("ALREADY_MINTED"),
            "after the block, the poll answers minted from CHAIN STATE: {jminted}"
        );

        // THE OWNER GATE, through the real route: same custodian, same confirmed deposit, only the owner
        // missing → REFUSED before any request is made. Refusing beats accepting and filing nothing.
        let (_c, jno) = route(&rt, "POST", "/wrapped_mint_execute", &body_no_owner);
        assert!(
            jno.contains("BAD_REQUEST:OWNER") && !jno.contains("\"minted\":true") && !jno.contains("REQUESTED"),
            "a mint with no account owner must be REFUSED — the note would be undiscoverable: {jno}"
        );

        // Replay the SAME foreign deposit → the poll answers the chain's state, and NOTHING new is pooled.
        let pooled_before = rt.lock().unwrap().node().mempool().all_tx_ids().len();
        let (_c, jr) = route(&rt, "POST", "/wrapped_mint_execute", &body_ok);
        assert!(
            jr.contains("ALREADY_MINTED") && !jr.contains("REQUESTED"),
            "a replayed deposit is answered from chain state, never re-requested: {jr}"
        );
        assert_eq!(
            rt.lock().unwrap().node().mempool().all_tx_ids().len(),
            pooled_before,
            "a replay pools no second object"
        );
    }

    /// ⛔ DB-327 — A STAKE-BEARING SUBMIT IS REFUSED AT THE DOOR, BEFORE ANY PROOF. A body carrying `stake_notes_hex`
    /// (the pre-DB-327 wallet's `cm ‖ amount ‖ nullifier` shape) answers 422 `STAKE_PAUSED` with a legible detail even
    /// though it carries no valid proof — the refusal comes before every gate — and nothing is pooled. CALIBRATION: the
    /// same body WITHOUT the field is not refused as a stake, so the refusal is keyed on the field alone.
    #[test]
    fn db327_a_stake_bearing_submit_is_refused_at_the_door_before_any_proof() {
        // TWO-PARTY-REVIEWED: a door refusal — nothing is admitted, so nothing can cross to a peer; the gossip half of
        // the same predicate is `admit_tx_shared`'s (lane-db224), pinned there on its own ingress path.
        let rt = fresh();
        let blob = hex_encode(&[9u8; 96]);
        let stake = hex_encode(&[0x5Au8; 72]);
        let with = format!("{{\"tx_as_hex\":\"{blob}\",\"stake_notes_hex\":\"{stake}\"}}");
        let (code, json) = route(&rt, "POST", "/submit_pq_tx", &with);
        assert_eq!(code, 422, "a stake-bearing submit is refused: {json}");
        assert!(
            json.contains("\"error\":\"STAKE_PAUSED\"") && json.contains("DB-237"),
            "the refusal names the pause and what re-opens it: {json}"
        );
        assert!(rt.lock().unwrap().node().mempool().is_empty(), "nothing was pooled");
        let without = format!("{{\"tx_as_hex\":\"{blob}\"}}");
        let (_, json2) = route(&rt, "POST", "/submit_pq_tx", &without);
        assert!(!json2.contains("STAKE_PAUSED"), "calibration: the refusal is keyed on the field alone: {json2}");
    }

    /// ⭐ DB-345 LIFTED — A BOND-BEARING SUBMIT IS JUDGED BY THE BOND GATES, AND A FORGED ONE POOLS NOTHING. With the pause
    /// gone, `/submit_pq_tx` with `bond_notes_hex` reaches the bond's own gates (the mandatory membership carrier, the welded
    /// bond carrier, the signed statement): a submit carrying none of them is refused and nothing is pooled. `/sign_bond`
    /// refuses a zero weight before it reads any key. ⛔ SINCE 2026-10-07 VALIDATOR BONDS ARE SAT-ONLY: the door refuses
    /// every bond-bearing submit first, with `Node::USDM_BOND_RETIRED` (the rogue-role cell
    /// `a_usdm_bond_a_rogue_producer_lays_with_its_proven_statement_seats_nothing_on_the_peer` pins the fold's half).
    #[test]
    fn db345_a_forged_bond_submit_pools_nothing_and_a_zero_weight_bond_signature_is_refused() {
        // TWO-PARTY-REVIEWED: a door refusal — nothing is admitted, so nothing can cross to a peer; the fold door is pinned
        // in node.rs on three nodes.
        let rt = fresh();
        let blob = hex_encode(&[9u8; 96]);
        let bond = hex_encode(&[0x31u8; 40]);
        let with = format!("{{\"tx_as_hex\":\"{blob}\",\"bond_notes_hex\":\"{bond}\"}}");
        let (code, json) = route(&rt, "POST", "/submit_pq_tx", &with);
        assert!(!json.contains("\"status\":\"OK\""), "a forged bond-bearing submit is refused: {json}");
        // ⛔ VALIDATOR BONDS ARE SAT-ONLY: refused at intake, keyed on the field, with the ruling named (before any proof).
        assert_eq!(code, 422, "a USDm bond submit is refused as such: {json}");
        assert!(json.contains("USDM_BOND_RETIRED"), "the refusal names the SAT-only rule and where to bond: {json}");
        assert!(rt.lock().unwrap().node().mempool().is_empty(), "⛔ a forged bond was pooled");
        let cm = hex_encode(&[7u8; 32]);
        let sign = format!("{{\"locked_cm_hex\":\"{cm}\",\"nullifier_hex\":\"{cm}\",\"weight\":0}}");
        let (scode, sjson) = route(&rt, "POST", "/sign_bond", &sign);
        assert_eq!(scode, 422, "a zero-weight bond statement is never signed: {sjson}");
        assert!(sjson.contains("SIGN_BOND_ZERO_WEIGHT"), "the refusal names the zero weight: {sjson}");
    }
}

#[cfg(all(test, feature = "pins-harness"))]
mod faucet_drip_replay_tests {
    //! LIVE INCIDENT 2026-09-02 (gate 29 scratch pair): node1's ledger replay folded to a root WITHOUT
    //! the faucet drip its wallet had already read as spendable — 146 REVERTs against a live target
    //! that contained it. A receive folded into the live accumulator must ALSO be in a record sidecar,
    //! or no restart can ever rebuild the map. Two parties: a producer runtime that drips, and a peer
    //! node that verifies the replay reproduces the producer's live root from the SAME records.
    use super::route;
    use super::tests::fresh_testnet;

}

#[cfg(all(test, feature = "pins-harness"))]
mod honest_answer_shape_tests {
    //! LANDING RUN 2026-09-04, items 8(a) and 3: the drip route claimed `"recorded":true` for three
    //! RAM-only stagings a restart destroys, and no served field could decompose the live
    //! records_held/record_top gap. Both pins run TWO NODES: the drip's settle is asserted on the
    //! peer that ingested the carrier block, never on what the producer's own call returned.
    //!
    //! ROOT-LAYER: these are the pins for two serve-layer edits whose values are PRODUCED by
    //! node.rs's own state (`pending_credit_notes` for the drip staging; `da_ord_mem`,
    //! `uns_spendfold_gap` and the spine cursor for the holding split). The routes project those
    //! producer-owned values; the pins assert the projection and the producer move together, on
    //! both nodes.
    //!
    //! MEASURED: 2026-09-04, my own /get_info read on the live pair (build 81578d55d825e09d):
    //! :27780 records_held 197 / record_top 7306 (7109 absent, `missing_records` naming 65),
    //! :28901 records_held 4099 / record_top 8627 (4528 absent) — and the drip route answering
    //! `recorded:true` for a staging the wallet then read as 0 owned / 0 spendable.
    //!
    //! MUST-STAY-GREEN: `a_faucet_drip_folded_live_is_reproducible_by_a_ledger_replay` (the staged
    //! credit still rides the next block — the stagings are KEPT, only the claim changed) and the
    //! full rpc_http route-table sweep.
    use super::route;
    use super::tests::fresh_testnet;

    /// CATCHES: the record-holding split failing its own sum law (the three classes must PARTITION
    /// the ordinal space: bytes_absent + present_unfolded + folded_held == record_top), the route
    /// serving a non-constant shape, or the split disagreeing between the two nodes after both hold
    /// the same block. The split exists so the live `records_held << record_top` gap (:27780 read
    /// 197/7306 on 2026-09-04 with no served field naming why) is one read instead of log
    /// archaeology.
    /// RED WITHOUT THE FIX: the route does not exist — `route()` answers 404 NOT_FOUND and the first
    /// assertion fails (confirmed by running this test with the route arm reverted: RED, then GREEN
    /// with the arm restored; the runs are recorded in the landing report).
    #[test]
    fn record_holding_split_sums_to_record_top_and_names_the_absent_class() {
        let node_a = fresh_testnet();
        let peer_node = fresh_testnet();
        let read = |rt: &super::Arc<super::Mutex<super::NodeRuntime<crate::transport::LoopbackTransport>>>,
                    tag: &str| {
            let (code, body) = route(rt, "GET", "/record_holding", "");
            assert_eq!(code, 200, "{tag}: the record-holding split answers: {body}");
            let f = |k: &str| {
                super::json_num_field(&body, k)
                    .unwrap_or_else(|| panic!("{tag}: field {k} missing: {body}"))
            };
            (
                f("record_top"),
                f("bytes_absent"),
                f("present_unfolded"),
                f("folded_held"),
                body,
            )
        };
        let (top0, abs0, unf0, fold0, body0) = read(&node_a, "fresh");
        assert_eq!(
            abs0 + unf0 + fold0,
            top0,
            "the three classes must PARTITION the ordinal space (fresh): {body0}"
        );
        // Stage a credit and produce the block that records it — the classes must MOVE with the
        // chain and the sum law must survive the move (a constant that cannot move is the
        // assertion-that-cannot-fail class §5 bans). peer_node ingests the same block, so the same
        // laws are asserted on what the SECOND party holds.
        let (dcode, dbody) = route(&node_a, "POST", "/faucet/drip", r#"{"amount":1000000}"#);
        assert_eq!(dcode, 200, "drip stages a credit: {dbody}");
        let blk = {
            let mut g = node_a.lock().unwrap();
            g.node_mut()
                .produce(
                    5000,
                    crate::hash::Hash32::hash(b"holding-carrier"),
                    crate::hash::Hash32::hash(b"miner"),
                )
                .expect("the block that records the credit")
        };
        {
            let mut v = peer_node.lock().unwrap();
            assert!(
                matches!(
                    v.node_mut().ingest_block(blk, 9_000),
                    crate::relay::RelayOutcome::Added(_)
                ),
                "peer_node must accept the carrier block"
            );
        }
        let (top1, abs1, unf1, fold1, body1) = read(&node_a, "node_a-after");
        assert_eq!(
            abs1 + unf1 + fold1,
            top1,
            "the sum law must survive a produce: {body1}"
        );
        assert!(
            top1 > top0,
            "a produced block advances the record ordinal space: {top0} -> {top1}"
        );
        assert!(
            fold1 > fold0,
            "the recorded block is held and fold-covered on node_a (fold-at-tip params): \
             folded_held {fold0} -> {fold1}; {body1}"
        );
        // THE SECOND PARTY: peer_node answers the same laws over what IT holds — its record space
        // advanced to node_a's and its split partitions exactly.
        let (ptop, pabs, punf, pfold, pbody) = read(&peer_node, "peer-after");
        assert_eq!(
            pabs + punf + pfold,
            ptop,
            "peer_node's three classes must partition its ordinal space: {pbody}"
        );
        assert_eq!(
            ptop, top1,
            "peer_node's record ordinal space must match node_a's after ingesting the same block: \
             {pbody}"
        );
        assert!(
            pfold > 0,
            "peer_node holds and fold-covers the record its ingest wrote: {pbody}"
        );
        // CONSTANT SHAPE: the same nine fields whether healthy or holed — never an id, address,
        // note, commitment, amount, key or owner.
        for k in [
            "record_top",
            "bytes_absent",
            "present_unfolded",
            "folded_held",
            "certified_position",
            "wanted_by_ordinal",
            "wanted_by_id",
            "da_wanted_ids",
            "da_wanted",
        ] {
            assert!(
                body1.contains(&format!("\"{k}\":")) && pbody.contains(&format!("\"{k}\":")),
                "constant response shape must carry {k} on both nodes: {body1} | {pbody}"
            );
        }
    }
}

/// ⭐⭐⭐ ONE ENCODING FOR A COPATH LEVEL ON THE WIRE — defined once, derived from the digest itself.
///
/// ⛔⛔⛔ WHY THIS IS A FUNCTION. It was an inline `format!("[{},{},{},{}]", d[0], d[1], d[2], d[3])` in
/// `/unspent_catchup`: a hard-coded FOUR against `spend_frontier::Digest4 =
/// poseidon2_compress::Digest = [u64; DIGEST_LANES]`, where `DIGEST_LANES` is EIGHT. Lanes 4..7 of every
/// copath level were dropped, so nothing could reconstruct the digest the node holds and a copath rebuilt
/// from the answer cannot fold to the live unspent root — the spend carrying it is refused at the door.
/// The wallet's parser made it a hard failure rather than a silent one: it filled an eight-lane
/// `empty_leaf()` by indexing a four-element array, an out-of-bounds index on the FIRST level of the
/// FIRST note.
///
/// ROOT-FIX-VERIFIED: the width is taken from the digest being encoded, so there is no number here for a
/// lane widening to outrun — the §AG class-9 lesson ("ONE codec per wire family; no hand-written width
/// near it") applied to the one route a wallet's spend witness is built from. Pinned by
/// `a_copath_level_carries_every_lane_of_the_digest`.
fn copath_level_json(d: &crate::spend_frontier::Digest4) -> String {
    let lanes: Vec<String> = d.iter().map(|l| l.to_string()).collect();
    format!("[{}]", lanes.join(","))
}

#[cfg(all(test, feature = "pins-harness"))]
mod db273_l4a_pins {
    /// ⭐ DB-273 §19.7 L4a — `/submit` reads no account target, carries none on the transaction and files none. A
    /// target (`note_cm ‖ bucket_id ‖ ek`) published a per-WALLET constant beside every payment and every change
    /// (`PqTx::account_targets`, `Block::account_targets`); the wallet builds none since L4a and reads no bucket since
    /// L5, so the RPC handlers are the last production writer.
    /// ROOT-LAYER: `/submit` is where a wallet's targets entered the node (the tx field and the local filing both
    /// took them from this intake); nothing else in the handlers ever produced one.
    /// MEASURED: the pre-L4a handlers READ — the intake read `account_targets_hex` twice and filed through
    /// `record_account_target` once; the calibration below runs the census over those exact lines and finds all three.
    /// MUST-STAY-GREEN: the note-clue intake and filing beside it (DB-330) are unchanged.
    /// TWO-PARTY-REVIEWED: a SOURCE census of the one door a wallet writes through. The crossing — a second node
    /// holding a received note with no target on the tx or block — is the real-pair journey at the end gate (§19.7
    /// pin (b)); the field itself is deleted, and censused away, at the re-genesis (L4b, pin (d)).
    #[test]
    fn db273_l4a_submit_reads_carries_and_files_no_account_target() {
        let needles = [["account_targets", "_hex"].concat(), ["record_account", "_target("].concat()];
        let census = |src: &str| -> Vec<String> {
            crate::harness::privacy::rpc_handler_half(src)
                .lines()
                .map(|l| l.find("//").map_or(l, |i| &l[..i]))
                .filter(|l| needles.iter().any(|n| l.contains(n.as_str())))
                .map(|l| l.trim().to_string())
                .collect()
        };
        let pre_l4a = [
            ["let raw_len = json_str_field(body, \"account", "_targets_hex\")"].concat(),
            ["json_str_field(body, \"account_targets", "_hex\")"].concat(),
            ["rt.node_mut().record_account", "_target(cm, bucket, ek, None);"].concat(),
        ]
        .join("\n");
        assert_eq!(census(&pre_l4a).len(), 3, "CALIBRATION: the census catches the intake reads and the filing");
        let hits = census(include_str!("rpc_http.rs"));
        assert!(
            hits.is_empty(),
            "⛔ DB-273 L4a: an RPC handler still takes or files an account target — a per-wallet id beside every \
             payment: {hits:?}"
        );
    }
}

#[cfg(all(test, feature = "pins-harness"))]
mod copath_wire_pins {
    /// DERIVED, NOT A HAND LIST (2026-09-17, §DC): the four-limb digest spelling `[{},{},{},{}]` is the
    /// pre-§AG width. It was widened for copath LEVELS through `copath_level_json` on 2026-09-13 and
    /// survived on `/unspent_catchup`'s `unspent_root` and the unspent-map dump's `node` — the wallet
    /// read the first as "malformed unspent_root limb" and refused every send on two real nodes. This pin
    /// reads THIS FILE and refuses any digest formatted as four limbs, so the class cannot return by
    /// adding a route.
    #[test]
    fn no_route_in_this_file_serves_a_digest_as_four_limbs() {
        let src = include_str!("rpc_http.rs");
        // Built from parts so this pin's own line never matches itself.
        let four = format!("[{}]", ["{}"; 4].join(","));
        let hits: Vec<usize> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains(&four) && !l.trim_start().starts_with("//"))
            .map(|(i, _)| i + 1)
            .collect();
        assert!(
            hits.is_empty(),
            "⛔ a route still spells a digest as four limbs at line(s) {hits:?} — use copath_level_json"
        );
    }

    /// ⭐⭐⭐ A COPATH LEVEL MUST CARRY EVERY LANE OF THE DIGEST — the pin for the §AG half-width defect
    /// that made a wallet unable to build ANY spend witness.
    ///
    /// ⭐ THE CALIBRATION IS THE ROUND TRIP, not the lane count alone: the emitted text is parsed back the
    /// way the wallet parses it and must reproduce the digest EXACTLY. A count check alone would pass a
    /// format that emitted eight zeros.
    #[test]
    fn a_copath_level_carries_every_lane_of_the_digest() {
        let d: crate::spend_frontier::Digest4 =
            core::array::from_fn(|i| (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        assert!(
            d.iter().all(|&l| l != 0),
            "PRECONDITION: every lane must be non-zero, or a format that drops lanes still round-trips"
        );
        let js = super::copath_level_json(&d);
        let inner = js
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|t| t.parse::<u64>().expect("each lane is a decimal u64"))
            .collect::<Vec<u64>>();
        assert_eq!(
            inner.len(),
            d.len(),
            "⛔⛔⛔ THE WIRE DROPS LANES: a copath level carries {} of the digest's {} lanes. A caller \
             cannot rebuild the digest this node holds, so the copath cannot fold to the live unspent \
             root and every spend carrying it is refused — which is a user unable to move their money.",
            inner.len(),
            d.len()
        );
        assert_eq!(
            inner.as_slice(),
            d.as_slice(),
            "the emitted level must round-trip to the SAME digest, lane for lane"
        );
    }

}

#[cfg(all(test, feature = "pins-harness"))]
mod status_door_tests {
    //! ⛔⛔⛔ A NODE THAT CANNOT TELL ANYONE ITS HEIGHT IS DOWN, WHATEVER IT IS DOING INSIDE.
    //!
    //! MEASURED on a freshly launched node, quiet machine, polled every 3 s from t=0
    //! (scratchpad `probe.out` / `probe2.out`):
    //!
    //! ```text
    //! [boot-timeline] handing off to RPC serve (bind) at 1ms
    //! BEFORE:  t=3s..t=100s  {"status":"OK","busy":true}     first height at t=103s
    //! AFTER:   t=3s          …"busy":true,"height":2,…       first height at t=3s (the poll interval)
    //! ```
    //!
    //! The node was mining throughout. `/get_info` takes `try_lock`, loses it to the drain, and falls
    //! back to a cache only warmed by whoever WINS the lock — so while the lock is busy the cache stays
    //! cold and the reply carries nothing. That is the wallet's "Starting your node…" on a healthy node,
    //! and the ecosystem gate's `node1 never served RPC` against a node that bound in 1 ms.
    //!
    //! This pin drives the door WITH THE RUNTIME LOCK HELD — the exact contended state — so it fails
    //! against the answer that shipped and passes against the published snapshot.
    use super::*;

    #[test]
    fn get_info_answers_with_a_real_height_while_the_runtime_lock_is_held() {
        let rt = tests::fresh();
        // Publish one tick's worth of state, exactly as the runtime does at the end of its drain.
        publish_live_status(41, 40, true, 0, false);
        // Hold the runtime lock: every `try_lock` in the handler now loses, which is the state a probe
        // meets on a busy node.
        let _held = rt.lock().expect("the runtime lock");
        let (code, body) = route(&rt, "GET", "/get_info", "");
        assert_eq!(code, 200, "a status probe is answered, never queued: {body}");
        assert!(
            body.contains("\"height\":41"),
            "⛔ the contended answer carries NO height — this is the 103-second blackout a user sees as \
             a node that never started. Got: {body}"
        );
        assert!(
            body.contains("\"busy\":true"),
            "…and it still says it is busy, so the reading is not mistaken for an idle node: {body}"
        );
    }

    #[test]
    fn before_the_first_tick_the_door_says_warming_rather_than_inventing_a_zero() {
        // ⛔ A ZERO HEIGHT IS NOT AN HONEST UNKNOWN. Reporting 0 before the runtime has published
        // anything reads as a stalled chain — the opposite of the truth on a node that is still coming
        // up. This arm is what stops the fix above from trading one lie for another.
        use std::sync::atomic::Ordering::Relaxed;
        let had = LIVE_PUBLISHED.swap(false, Relaxed);
        let json = busy_info_json();
        LIVE_PUBLISHED.store(had, Relaxed);
        assert!(
            json.contains("\"warming\":true") && !json.contains("\"height\""),
            "⛔ an unpublished node must say it is warming, not claim a height it does not have: {json}"
        );
    }
}

#[cfg(all(test, feature = "pins-harness"))]
mod pool_without_gossip_tests {
    /// ⛔⛔ DB-335 — THE CLASS, NOT THE SPELLING: A NODE'S OWN OBJECT ENTERS ITS POOL ONLY THROUGH THE MARKING DOOR.
    ///
    /// The scan below matches one spelling in this file. Every node-level publication reached the pool one call deeper
    /// (`Node::ingest_tx` inside a `publish_*` / `execute_*`), where no needle here could see it, and none of them
    /// gossiped — READ 2026-09-27, eight sites. `Node::pool_own_publication` is the one door a node's own object now
    /// enters its pool by; it marks the object, and the runtime re-sends it until a block carries it. This reads node.rs
    /// and requires that door to be the ONLY `self.ingest_tx(` there, so a publication written tomorrow is caught by rule.
    #[test]
    fn every_node_level_publication_enters_the_pool_through_the_marking_door() {
        let src = include_str!("node.rs");
        // Built from parts so no line of this pin could ever be counted by a scan of its own kind.
        let needle = ["self", ".ingest", "_tx("].concat();
        let hits: Vec<usize> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                !t.starts_with("//") && t.contains(&needle)
            })
            .map(|(i, _)| i + 1)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "⛔⛔ DB-335: node.rs pools a node-built object through the gossip admission door at {} site(s) (lines \
             {hits:?}); each must go through `pool_own_publication`, which marks it so the runtime gossips it until a \
             block carries it",
            hits.len()
        );
        let door = src.find("fn pool_own_publication(").expect("the marking door exists");
        let body_end = src[door..].find("\n    }\n").map(|e| door + e).expect("its body ends");
        assert!(
            src[door..body_end].contains(&needle),
            "the one remaining gossip-admission call must be the marking door's own"
        );
    }

    /// ⛔⛔⛔ NO REQUEST HANDLER MAY POOL A CHAIN OBJECT WITHOUT GOSSIPING IT.
    ///
    /// `NodeRuntime::ingest_tx` pools a transaction on THIS node and does nothing else.
    /// `NodeRuntime::submit_tx` / `submit_tx_prechecked` pool it AND queue `WireMsg::Tx`, which is the
    /// only reason a peer ever sees it. A door that reaches for the first one has published nothing: the
    /// object settles only if THIS node wins authorship, so whether a user's payment lands depends on
    /// which node they happened to reach — a race on block production rather than a property of the
    /// payment. That is the same defect `PqTx::account_targets` and `PqTx::spend_or_decoy` exist to kill,
    /// arriving through a different door.
    ///
    /// ⭐ MEASURED, NOT FEARED (ecosystem gate, 2026-09-23). `/faucet/drip` pooled its `BridgeCredit`
    /// with `node_mut().ingest_tx`, returned `"status":"OK"`, and the credit never reached node 2. Node 1
    /// was 84 blocks behind and so built no template (correct, per isNearlySynced), so the object sat in
    /// one pool forever and the wallet's balance stayed 0.00 with every door reporting success.
    /// `/register_wrapped_asset` held the identical shape and had simply never been exercised across
    /// nodes.
    ///
    /// ⛔ THIS IS A DERIVED SCAN, NOT A HAND LIST. It reads the route file and flags any `ingest_tx`
    /// reached through `node_mut()` from a handler, so a NEW door written tomorrow is caught by the same
    /// rule rather than by someone remembering. Test-only helpers (`ingest_tx_unverified`) are a
    /// different function and are not matched.
    #[test]
    fn no_request_handler_pools_a_chain_object_without_gossiping_it() {
        let src = include_str!("rpc_http.rs");
        // ⛔ EXCLUDE THIS PIN'S OWN TEXT — the needle is written here, and a self-referential scan that
        //    counts itself measures its own source instead of the code under audit.
        let scanned = src.split_once("mod pool_without_gossip_tests").map_or(src, |(above, _)| above);
        let offenders: Vec<usize> = scanned
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let l = l.trim_start();
                !l.starts_with("//") && l.contains("node_mut().ingest_tx(")
            })
            .map(|(i, _)| i + 1)
            .collect();
        assert!(
            offenders.is_empty(),
            "⛔⛔⛔ {} REQUEST HANDLER(S) POOL A CHAIN OBJECT WITHOUT GOSSIPING IT, at rpc_http.rs \
             line(s) {:?}. `node_mut().ingest_tx` pools on THIS node only — the object then settles just \
             if this node wins authorship, so the user's payment becomes a race on block production. Use \
             `submit_tx` (or `submit_tx_prechecked` when the proof was already verified), which pools AND \
             queues `WireMsg::Tx`. MEASURED: the faucet drip did exactly this and reported OK while the \
             credit reached no other node.",
            offenders.len(),
            offenders
        );
    }

    /// ⭐ THE CALIBRATION — the scan must be able to SEE the shape it refuses, or a green run means
    /// nothing. Without this, a regex that matched no line would read exactly like a clean tree.
    #[test]
    fn the_pool_without_gossip_scan_detects_the_shape_it_refuses() {
        let planted = "        g.node_mut().ingest_tx(some_object.as_pq_tx(bits, &clue))\n";
        let hits = planted
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                !l.starts_with("//") && l.contains("node_mut().ingest_tx(")
            })
            .count();
        assert_eq!(hits, 1, "the scan cannot see a planted pool-without-gossip call — it proves nothing");
        let commented = "        // g.node_mut().ingest_tx(x)\n";
        let false_hits = commented
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                !l.starts_with("//") && l.contains("node_mut().ingest_tx(")
            })
            .count();
        assert_eq!(false_hits, 0, "the scan flags PROSE — a comment naming the shape is not the shape");
    }
}
