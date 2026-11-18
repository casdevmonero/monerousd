// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// REAL-CODE e2e harness driver: ONE real MonerousD wallet per process, driven over stdin, talking ONLY to the node
// named by `MONEROUSD_NODE_URL` with its note store isolated at `MONEROUSD_WALLET_DATA`. It is LONG-RUNNING so the
// wallet's in-memory state (owned-note set, self-built witness book, scan cursor) persists across commands EXACTLY
// like the desktop/phone app — so a "balance drops to 0 on refresh" or "owned note witness not caught up" bug
// reproduces here bit-for-bit. NO test logic, NO reconstructed crypto, NO stand-in lives here: every operation is a
// direct call into `monerousd_wallet_v2_lib::harness`, which is a thin wrapper over the EXACT functions the Tauri UI
// invokes (wallet_restore / wallet_address / wallet_balance_impl / wallet_send). Two of these processes pointed at
// two REAL peered nodes reproduce a device-to-device send with full fidelity; the driver asserts the real outcome.
//
// Protocol: each stdin line is one command; each result is one JSON line on stdout (flushed):
//   address                     -> { ok, op:"address", result:{ address } }
//   balance                     -> { ok, op:"balance", result:{ usdm, atomic, ... } }
//   send <to_address> <usdm>    -> { ok, op:"send",    result:{ ... } | error }
//   sell <usdm> <asset> <payout_to>  -> { ok, op:"sell",    result:{ ... } | error }   (the Sell screen: burn + /peg_out_execute)
//   buy <BTC|XMR> <usdm>        -> { ok, op:"buy",     result:{ swap_id, deposit_address, pay_usd, ... } }
//   mint <swap_id>              -> { ok, op:"mint",    result:{ minted, pending, mint_height, ... } }
//   swap <swap_id>              -> { ok, op:"swap",    result:{ status, ... } }
//   bondrewards [on|off]                -> { ok, op:"bondrewards", result:{ on } } (§BR-11: refresh bonds new mining rewards)
//   tokencreate <SYM> <name> <whole_supply> -> { ok, op:"tokencreate", result:{ asset_id, supply_atomic, ... } }
//   dsoldeploy <code_hex> <height_class> <name> <fee_usdm> -> { ok, op:"dsoldeploy", result:{ cid, manifest, view_ek_hex, leaf_hex, ... } } (§BR-12 F13)
//   dsolcall <params_json>      -> { ok, op:"dsolcall", result:{ cid, tx_hash, publisher_fee_usd, ... } } (the UI's call, without the UI)
//   veil_backend_deploy <name> <source_file> <fee_usdm> -> { result:{ cid, files:[{path,hex}] } } (assemble + deploy a site's back end)
//   veil_backend_read <name> <keys_json>   -> { result:{ values:{ key: {word}|{text}|null } } } (keys: ["n", {"map":"m","key":"0"}])
//   veil_backend_call <name> <entry> <argv_hex> -> { result:{ tx_hash, ... } } (a write, paid and proven by this wallet)
//   veil_backend_snapshot <name>           -> { result:{ path, hex } | null }
//   veil_seal <name> <text_hex> / veil_open <name> <sealed> -> a person's own sealed text, and back
//   quit                        -> exit 0
// A failed op prints { ok:false, op, error } and the process keeps running (so the driver decides pass/fail).

use monerousd_wallet_v2_lib::harness;
use monerousd_wallet_v2_lib::{checkout, proof_tags, sale, vault_ops, veil_site};
use std::io::{BufRead, Write};

fn emit(ok: bool, op: &str, payload: Result<serde_json::Value, String>) {
    let line = match payload {
        Ok(v) => serde_json::json!({ "ok": ok, "op": op, "result": v }),
        Err(e) => serde_json::json!({ "ok": false, "op": op, "error": e }),
    };
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// The tap in progress in THIS process — a device holds its own side of one tap in memory between its steps
/// (`tapcharge-*` below; the protocol steps are `moneropay_ble::tap_*`).
#[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
static TAP_MERCHANT: std::sync::Mutex<Option<monerousd_wallet_v2_lib::moneropay_ble::TapMerchant>> =
    std::sync::Mutex::new(None);
#[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
static TAP_PAYER: std::sync::Mutex<Option<monerousd_wallet_v2_lib::moneropay_ble::TapPayer>> =
    std::sync::Mutex::new(None);

/// One crossing's frames as a single whitespace-free JSON token (the driver relays it to the other device).
fn frames_json(frames: &[Vec<u8>]) -> serde_json::Value {
    serde_json::json!({ "frames": frames.iter().map(hex::encode).collect::<Vec<_>>() })
}

/// The frames the other device put on the air, from the JSON array the driver relayed.
fn frames_arg(arg: &str) -> Result<Vec<Vec<u8>>, String> {
    let hexes: Vec<String> = serde_json::from_str(arg).map_err(|e| format!("frames are not a JSON array: {e}"))?;
    hexes.iter().map(|h| hex::decode(h).map_err(|e| format!("a frame is not hex: {e}"))).collect()
}

/// ⭐ ONE-SHOT MODE FOR macOS TCC-GRANTED EXECUTION (BLE).
///
/// MEASURED 2026-08-13: a BARE binary can NEVER hold a Bluetooth grant — macOS keys TCC to the launching
/// app's identity, so `wallet-harness` piped from a shell aborts (SIGABRT/exit 134) the instant it touches
/// CoreBluetooth, while the SAME code inside the granted `.app` scans fine. The durable fix is to run the
/// harness AS AN APP BUNDLE (`open -n -a MUSDHarness.app --args <config.json>`), which LaunchServices makes
/// its own responsible process — one prompt, then the grant persists for every later run.
///
/// Launched that way there is no stdin/stdout, so the run is described by a JSON config and the replies are
/// written to a file: {"seed_file","node_url","data_dir","cmds":[...],"out"}. Identical command dispatch as
/// the stdin loop — `serve`, the one command table, no test-only shortcut. cons: one small JSON per role per run (scratch
/// files, deleted freely); no behaviour change for the normal stdin mode.
fn run_oneshot(cfg_path: &str) -> ! {
    let raw = std::fs::read_to_string(cfg_path).unwrap_or_else(|e| panic!("cfg {cfg_path}: {e}"));
    let cfg: serde_json::Value = serde_json::from_str(&raw).expect("cfg json");
    let g = |k: &str| cfg.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let out_path = g("out");
    let seed = std::fs::read_to_string(g("seed_file")).expect("seed file").trim().to_string();
    std::env::set_var("MONEROUSD_NODE_URL", g("node_url"));
    std::env::set_var("MONEROUSD_WALLET_DATA", g("data_dir"));
    std::env::set_var("MONEROUSD_NET", "testnet");
    let mut log: Vec<String> = Vec::new();
    let mut push = |op: &str, ok: bool, v: serde_json::Value| {
        log.push(serde_json::json!({"ok": ok, "op": op, "result": v}).to_string());
        let _ = std::fs::write(&out_path, log.join("\n"));
    };
    match harness::restore(&seed) {
        Ok(v) => push("restore", true, v),
        Err(e) => {
            push("restore", false, serde_json::json!({ "error": e }));
            std::process::exit(2);
        }
    }
    for c in cfg.get("cmds").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let line = c.as_str().unwrap_or("").to_string();
        serve(&line, &mut |ok, op, r| match r {
            Ok(v) => push(op, ok, v),
            Err(e) => push(op, false, serde_json::json!({ "error": e })),
        });
    }
    std::process::exit(0);
}

/// ⭐ THE ONE COMMAND TABLE — the stdin session and the one-shot (app-bundle) mode both serve every command here; they
/// differ only in where a reply goes (`out`).
///
/// MEASURED sim-20261006-181451 (T2): the one-shot mode kept its OWN fifteen-arm table under a doc line claiming "identical
/// command dispatch as the stdin loop — one code path", so the journey simulator's `ladderpost` (and every DEX, name,
/// profile, letter, unbond and tap command it drives) came back `unsupported one-shot cmd` while the session served it.
/// Two tables for one protocol is two protocols; there is now one, and no command exists in one mode only.
fn serve(line: &str, out: &mut dyn FnMut(bool, &str, Result<serde_json::Value, String>)) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // helper: parse a USDm amount arg, then run `f` — surfaces a bad amount as a loud error (no silent default).
    let amt_then = |amt: &str, f: &dyn Fn(f64) -> Result<serde_json::Value, String>| {
        amt.parse::<f64>().map_err(|e| format!("bad amount '{amt}': {e}")).and_then(f)
    };
    match parts.as_slice() {
        // ⭐ HOLD THIS WALLET ALIVE — the shape the desktop and phone apps actually run.
        //
        // ⛔ A WALLET THAT IS RESTARTED BETWEEN EVERY POLL IS NOT THE THING WE SHIP. This driver's own
        // header says it is LONG-RUNNING *"so the wallet's in-memory state (owned-note set, self-built
        // witness book, scan cursor) persists across commands EXACTLY like the desktop/phone app"*, and
        // a caller that pipes `detect\nbalance` and exits loses exactly that. It matters now because
        // spend authority is a MAINTAINED recursive carrier (`nf_carrier`): a wallet that starts over
        // every few seconds never gets to stand on the chain tip, so it would read 0 spendable while
        // holding the money — and the driver would be measuring a process model nobody runs.
        //
        // This is not a wait-for-a-condition and decides nothing: it holds the process for a stated
        // number of milliseconds so the background follower keeps following, exactly as the app does
        // between a user's taps.
        ["hold", ms] => {
            let ms: u64 = ms.parse().unwrap_or(1_000);
            std::thread::sleep(std::time::Duration::from_millis(ms));
            out(true, "hold", Ok(serde_json::json!({ "held_ms": ms })));
        }
        // ⭐ goods spec §9.1 — PROTECTED PURCHASES, the wallet's own functions (`vault_ops`), so a real-node check and
        // the merchant's checkout helper drive exactly what the app's buttons call. Messages are compact JSON (no
        // spaces); a title is one word.
        ["purchase_request", amount, deadline_ms, title] => {
            let r = amt_then(amount, &|a| {
                let deadline: u64 = deadline_ms.parse().map_err(|e| format!("bad deadline '{deadline_ms}': {e}"))?;
                vault_ops::order_request(title, (a * 1e8).round() as u64, deadline)
            });
            out(r.is_ok(), "purchase_request", r);
        }
        ["purchase_accept", amount, request] => {
            let r = amt_then(amount, &|a| {
                let req: serde_json::Value = serde_json::from_str(request).map_err(|e| format!("bad request: {e}"))?;
                vault_ops::order_accept(&req, (a * 1e8).round() as u64, "sale")
            });
            out(r.is_ok(), "purchase_accept", r);
        }
        ["purchase_fund", accept] => {
            let r = serde_json::from_str::<serde_json::Value>(accept).map_err(|e| format!("bad accept: {e}")).and_then(|a| vault_ops::order_fund(&a));
            out(r.is_ok(), "purchase_fund", r);
        }
        ["purchase_funded", request, funded] => {
            let r = serde_json::from_str::<serde_json::Value>(request)
                .and_then(|q| serde_json::from_str::<serde_json::Value>(funded).map(|f| (q, f)))
                .map_err(|e| format!("bad message: {e}"))
                .and_then(|(q, f)| vault_ops::order_funded(&q, &f, "sale"));
            out(r.is_ok(), "purchase_funded", r);
        }
        ["purchase_status", id] => {
            let r = vault_ops::order_status(id);
            out(r.is_ok(), "purchase_status", r);
        }
        ["purchase_list"] => {
            let all: Vec<serde_json::Value> = vault_ops::open_orders().iter().filter_map(|o| vault_ops::order_status(&o.id).ok()).collect();
            out(true, "purchase_list", Ok(serde_json::json!({ "purchases": all })));
        }
        ["purchase_code", id] => {
            let r = vault_ops::order_code(id).map(|c| serde_json::json!({ "code": c }));
            out(r.is_ok(), "purchase_code", r);
        }
        ["purchase_check_code", code] => {
            let r = vault_ops::order_code_is_good(code).map(|good| serde_json::json!({ "good": good }));
            out(r.is_ok(), "purchase_check_code", r);
        }
        ["purchase_release", code] => {
            let r = vault_ops::order_release(code);
            out(r.is_ok(), "purchase_release", r);
        }
        ["purchase_refund_code", id] => {
            let r = vault_ops::order_refund_code(id).map(|c| serde_json::json!({ "code": c }));
            out(r.is_ok(), "purchase_refund_code", r);
        }
        ["purchase_refund", code] => {
            let r = vault_ops::order_refund(code);
            out(r.is_ok(), "purchase_refund", r);
        }
        ["purchase_reclaim", id] => {
            let r = vault_ops::order_reclaim(id);
            out(r.is_ok(), "purchase_reclaim", r);
        }
        // ⭐ goods spec §8 — PAYING A SHOP FROM ITS LINK, the wallet's own functions (`checkout`): what the app's one
        // confirmation sheet calls. The harness is its own consent, as for every other command here.
        ["checkout_offer", link] => {
            let r = checkout::offer(link);
            out(r.is_ok(), "checkout_offer", r);
        }
        ["checkout_pay", link] => {
            let r = checkout::pay(link, &|_sentence| Ok(()));
            out(r.is_ok(), "checkout_pay", r);
        }
        ["checkout_hand_over", id] => {
            let r = checkout::hand_over(id);
            out(r.is_ok(), "checkout_hand_over", r);
        }
        ["checkout_status", id] => {
            let r = checkout::status(id);
            out(r.is_ok(), "checkout_status", r);
        }
        // ⭐ A SALE BETWEEN TWO PEOPLE, by link and private letters (`sale`): what the Merchant and Orders pages call.
        ["sale_offer", amount, hours, title] => {
            let r = amt_then(amount, &|a| {
                let h: u64 = hours.parse().map_err(|e| format!("bad hours '{hours}': {e}"))?;
                sale::offer(title, (a * 1e8).round() as u64, h, None)
            });
            out(r.is_ok(), "sale_offer", r);
        }
        ["sub_offer", amount, period_hours, title] => {
            let r = amt_then(amount, &|a| {
                let p: u64 = period_hours.parse().map_err(|e| format!("bad period '{period_hours}': {e}"))?;
                sale::offer_every(title, (a * 1e8).round() as u64, 0, p, None)
            });
            out(r.is_ok(), "sub_offer", r);
        }
        ["sale_cancel", id] => {
            let r = sale::cancel(id);
            out(r.is_ok(), "sale_cancel", r);
        }
        ["sale_read", link] => {
            let r = sale::read(link);
            out(r.is_ok(), "sale_read", r);
        }
        ["sale_buy", link] => {
            let r = sale::buy(link, None, &|_sentence| Ok(()));
            out(r.is_ok(), "sale_buy", r);
        }
        // a sale with a deposit and a delivery bond (either may be 0), a pickup at a relay, and the relay's side
        ["sale_offer_terms", amount, hours, deposit, bond, title] => {
            let r = amt_then(amount, &|a| {
                let h: u64 = hours.parse().map_err(|e| format!("bad hours '{hours}': {e}"))?;
                let part = |s: &str| s.parse::<f64>().map(|x| (x * 1e8).round() as u64).map_err(|e| format!("bad amount '{s}': {e}"));
                sale::offer_terms(title, (a * 1e8).round() as u64, h, 0, part(deposit)?, part(bond)?, None)
            });
            out(r.is_ok(), "sale_offer_terms", r);
        }
        ["sale_buy_at", link, relay] => {
            let r = sale::buy(link, Some(relay), &|_sentence| Ok(()));
            out(r.is_ok(), "sale_buy_at", r);
        }
        ["relay_on"] => {
            sale::relay_set(true);
            out(true, "relay_on", Ok::<_, String>(sale::pickups()));
        }
        ["relay_pickups"] => out(true, "relay_pickups", Ok::<_, String>(sale::pickups())),
        ["relay_received", id] => {
            let r = sale::parcel_received(id);
            out(r.is_ok(), "relay_received", r);
        }
        ["sale_deposits"] => out(true, "sale_deposits", Ok::<_, String>(sale::deposits())),
        // ⭐ MONEROUSD VEIL — publish a folder as `<name>.mud` through this wallet's node, and read the name back.
        ["veil_publish", name, dir] => {
            fn walk(base: &std::path::Path, at: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), String> {
                for e in std::fs::read_dir(at).map_err(|e| format!("cannot read {}: {e}", at.display()))? {
                    let p = e.map_err(|e| e.to_string())?.path();
                    if p.is_dir() {
                        walk(base, &p, out)?;
                    } else {
                        let rel = p.strip_prefix(base).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
                        out.push((rel, std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?));
                    }
                }
                Ok(())
            }
            let mut files = Vec::new();
            let r = walk(std::path::Path::new(dir), std::path::Path::new(dir), &mut files)
                .and_then(|()| veil_site::pack(&files))
                .and_then(|_| usdmd_node::veil::pack_site(&files).ok_or_else(|| "the folder could not be packed".to_string()))
                .and_then(|blob| veil_site::publish(name, &blob, &|_sentence| Ok(())));
            out(r.is_ok(), "veil_publish", r);
        }
        ["veil_site", name] => {
            let r = veil_site::site(name);
            out(r.is_ok(), "veil_site", r);
        }
        // ⭐ A SITE'S BACK END (Veil spec §12): the core functions the Publish screen and a page's bridge call.
        ["veil_backend_deploy", name, source_file, fee] => {
            let r = std::fs::read_to_string(source_file)
                .map_err(|e| format!("cannot read {source_file}: {e}"))
                .and_then(|src| fee.parse::<f64>().map_err(|e| e.to_string()).map(|f| (src, f)))
                .and_then(|(src, f)| veil_site::backend_deploy(name, &src, f, veil_site::BACKEND_CLASS_DEFAULT));
            out(r.is_ok(), "veil_backend_deploy", r);
        }
        ["veil_backend_example"] => {
            let r = veil_site::assemble("");
            out(r.is_ok(), "veil_backend_example", r);
        }
        ["veil_backend_read", name, keys_json] => {
            let r = serde_json::from_str::<serde_json::Value>(keys_json).map_err(|e| format!("bad keys: {e}")).and_then(|k| veil_site::backend_read(name, &k));
            out(r.is_ok(), "veil_backend_read", r);
        }
        ["veil_backend_call", name, entry, argv_hex] => {
            let r = hex::decode(argv_hex).map_err(|e| format!("bad argv: {e}")).and_then(|a| veil_site::backend_call(name, entry, &a));
            out(r.is_ok(), "veil_backend_call", r);
        }
        ["veil_backend_snapshot", name] => {
            let r = veil_site::backend_snapshot(name).map(|s| match s {
                Some((path, b)) => serde_json::json!({ "path": path, "hex": hex::encode(b) }),
                None => serde_json::Value::Null,
            });
            out(r.is_ok(), "veil_backend_snapshot", r);
        }
        ["veil_seal", name, text_hex] => {
            let r = hex::decode(text_hex)
                .map_err(|e| e.to_string())
                .and_then(|b| String::from_utf8(b).map_err(|e| e.to_string()))
                .and_then(|t| veil_site::seal(name, &t))
                .map(serde_json::Value::String);
            out(r.is_ok(), "veil_seal", r);
        }
        ["veil_open", name, sealed] => {
            let r = veil_site::open(name, sealed).map(serde_json::Value::String);
            out(r.is_ok(), "veil_open", r);
        }
        // ⭐ VEIL STORAGE: what holding bytes costs and who is paid; bytes stored and read back by their root alone.
        ["veil_quote", root, len] => {
            let r = len.parse::<u64>().map_err(|e| e.to_string()).and_then(|l| veil_site::storage_quote(root, l));
            out(r.is_ok(), "veil_quote", r);
        }
        ["veil_store", file] => {
            let r = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}")).and_then(|b| veil_site::store(&b));
            out(r.is_ok(), "veil_store", r);
        }
        // LOCAL-STORAGE-REQUIRED: this is the check harness, not the wallet: a real-node check names a file and compares
        // the bytes read through a node with the bytes it stored, and a check cannot compare what it cannot read. No
        // wallet or node state is in the file and nothing reads it back but the check that named it.
        // bound: one file per `veil_read` a check runs, the size of the bytes read (at most one stored blob, 64 MiB),
        // in the check's own temporary folder; nothing per block, per note or per height.
        ["veil_read", root, to, wait] => {
            let r = veil_site::read(root, wait.parse().unwrap_or(120))
                .and_then(|b| std::fs::write(to, &b).map(|()| serde_json::json!({ "bytes": b.len(), "blake3": blake3::hash(&b).to_hex().to_string() })).map_err(|e| format!("cannot write {to}: {e}")));
            out(r.is_ok(), "veil_read", r);
        }
        // ⭐ A DOWNLOAD: list a file for sale; list and save the downloads that arrived.
        ["sale_offer_download", title, amount_usdm, hours, file] => {
            let name = std::path::Path::new(file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "download".to_string());
            let r = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}")).and_then(|bytes| {
                let amount = (amount_usdm.parse::<f64>().map_err(|e| e.to_string())? * 1e8).round() as u64;
                sale::offer_download(title, amount, hours.parse().map_err(|_| "hours is a number".to_string())?, &name, &bytes, None)
            });
            out(r.is_ok(), "sale_offer_download", r);
        }
        ["sale_downloads"] => out(true, "sale_downloads", Ok::<_, String>(sale::downloads())),
        // ⭐ THE DOORSTEP: name the parcel; prove the carrier's delivery notice (a saved email file).
        ["sale_shipped", id, tracking] => {
            let r = sale::shipped(id, tracking);
            out(r.is_ok(), "sale_shipped", r);
        }
        ["sale_delivered", id, eml] => {
            let r = std::fs::read(eml).map_err(|e| format!("cannot read {eml}: {e}")).and_then(|b| sale::delivered(id, &b));
            out(r.is_ok(), "sale_delivered", r);
        }
        ["sale_carriers"] => out(true, "sale_carriers", Ok::<_, String>(serde_json::json!({ "carriers": sale::accepted_carriers() }))),
        // the buyer's own act: a seller's tracking number is only an offer until this accepts it
        ["sale_tracking_offers"] => out(true, "sale_tracking_offers", Ok::<_, String>(sale::tracking_offers())),
        ["sale_accept_tracking", id] => {
            let r = sale::accept_tracking(id);
            out(r.is_ok(), "sale_accept_tracking", r);
        }
        // an arrived download is written to the downloads folder (`MONEROUSD_DOWNLOADS`) by itself; this writes one
        // whose first write did not succeed, and says where the file is
        ["sale_download", id] => {
            let r = sale::download_save(id);
            out(r.is_ok(), "sale_download", r);
        }
        ["sale_have", id] => {
            let r = sale::i_have_it(id);
            out(r.is_ok(), "sale_have", r);
        }
        ["sale_calloff", id] => {
            let r = sale::call_off(id);
            out(r.is_ok(), "sale_calloff", r);
        }
        ["sale_sync"] => {
            let r = sale::sync();
            out(r.is_ok(), "sale_sync", r);
        }
        // ⭐ PROOF TAGS — a verifier's key, a business's bundle for it, and the verifier's check (`proof_tags`).
        ["prooftag_key", label] => {
            let r = proof_tags::verifier_key(label);
            out(r.is_ok(), "prooftag_key", r);
        }
        ["prooftag_income"] => {
            let r = proof_tags::income_summary();
            out(r.is_ok(), "prooftag_income", r);
        }
        ["prooftag_make", verifier_key, context] => {
            let r = proof_tags::bundle_make(verifier_key, context, None);
            out(r.is_ok(), "prooftag_make", r);
        }
        ["prooftag_check", label, bundle] => {
            let r = serde_json::from_str::<serde_json::Value>(bundle).map_err(|e| format!("bad bundle: {e}")).and_then(|b| proof_tags::bundle_check(&b, label));
            out(r.is_ok(), "prooftag_check", r);
        }
        // The shop's side of a plain charge: has THIS charge (by its signed nonce) been paid in full?
        ["chargeawait", nonce, atomic] => {
            let r = atomic.parse::<u64>().map_err(|e| format!("bad atomic amount '{atomic}': {e}")).and_then(|a| harness::charge_await(nonce, a));
            out(r.is_ok(), "chargeawait", r);
        }
        // REAL-RADIO BLE loopback. Exposed here so it can be run from inside the SIGNED APP BUNDLE,
        // which is the only context macOS grants Bluetooth to: a bare `cargo test` binary has no
        // NSBluetoothAlwaysUsageDescription and CoreBluetooth answers CBManagerState.unauthorized, so
        // the merchant never advertises and every tap times out with no explanation.
        // ⭐ TWO-ENDPOINT TAP, THE REAL SHAPE. `bletap` (loopback) is ONE process talking to itself: it
        // exercises the OTA framing but proves nothing about two devices paying each other, which is the
        // whole point of a tap. These two commands are the merchant and payer HALVES, run as separate
        // processes — the identical code path two physical devices run, with nothing shared in memory.
        //   device 1:  blemerchant <secs>
        //   device 2:  blepay <secs>
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["blemerchant", secs] | ["blemerchant", secs, _] => {
            let hold: u64 = secs.parse().unwrap_or(30);
            let amount_usdm: f64 = parts.get(2).and_then(|a| a.parse().ok()).unwrap_or(0.5);
            let atomic = (amount_usdm * 100_000_000.0).round() as u64;
            // Seal a PAYABLE charge (own receive address + amount) — a label charge can never settle.
            // See the one-shot merchant for the measurement that found this.
            let my_addr = harness::address()
                .ok()
                .and_then(|v| v.get("address").and_then(|a| a.as_str()).map(|s| s.to_string()))
                .unwrap_or_default();
            let charge = serde_json::json!({
                "v": 1, "to": my_addr, "atomic": atomic, "memo": "MUSD-charge-v1|two-device-tap"
            })
            .to_string()
            .into_bytes();
            let r = monerousd_wallet_v2_lib::moneropay_ble::start_merchant(charge)
                .map(|h| {
                    // Advertise for the whole window so the OTHER process can find us, then report what
                    // the radio actually did — never just "started".
                    std::thread::sleep(std::time::Duration::from_secs(hold));
                    let st = h.status_json();
                    h.stop();
                    st
                });
            out(r.is_ok(), "blemerchant", r)
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["blepay", secs] => {
            let wait: u64 = secs.parse().unwrap_or(30);
            let r = monerousd_wallet_v2_lib::moneropay_ble::pay_nearby(
                std::time::Duration::from_secs(wait),
            )
            .and_then(|o| {
                // ⛔ A TAP THAT OPENS A CHARGE AND STOPS IS NOT A PAYMENT. `pay_nearby` returns the opened
                // charge; nothing settled it, so the radio half worked and no money ever moved. Read the
                // amount and the merchant's address out of the charge the merchant SEALED, and broadcast
                // the same `wallet_send` the Send button calls — one code path for a tap and a manual send.
                let text = String::from_utf8_lossy(&o.charge_bytes).to_string();
                let parsed: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| format!("the opened charge is not JSON ({e}): {text}"))?;
                let to = parsed
                    .get("to")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("the charge names no recipient, so it cannot be paid: {text}"))?;
                let atomic = parsed
                    .get("atomic")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| format!("the charge names no amount: {text}"))?;
                let usdm = atomic as f64 / 100_000_000.0;
                let sent = monerousd_wallet_v2_lib::harness::send(to, usdm)?;
                Ok(serde_json::json!({
                    "opened_len": o.charge_bytes.len(),
                    "charge_utf8": text,
                    "rssi_dbm": o.rssi_dbm,
                    "distance_cm": o.distance_cm,
                    "settled_usdm": usdm,
                    "send_result": sent,
                }))
            });
            out(r.is_ok(), "blepay", r)
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["bletap"] => {
            // ⛔ THE RADIO MUST FAIL LOUD — MEASURED 2026-08-13: both BLE verbs died with NO output at
            // all (no emit line, no panic), so "radio denied" (macOS Bluetooth TCC for a terminal
            // binary), "radio hung", and "verb never ran" were indistinguishable. A marker line proves
            // the arm ran; a watchdog thread turns a silent death into a named, bounded verdict.
            // cons: one spawned thread per invocation + a 45s worst-case wait; cons otherwise: none.
            eprintln!("[ble] bletap: selftest starting (loopback, 30s window) — if this process dies                           with no further ble line, macOS Bluetooth permission (TCC) killed it silently");
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let charge = b"MUSD-charge-v1|tap-selftest".to_vec();
                let r = monerousd_wallet_v2_lib::moneropay_ble::selftest_loopback(
                    charge,
                    std::time::Duration::from_secs(30),
                );
                let _ = tx.send(r);
            });
            match rx.recv_timeout(std::time::Duration::from_secs(45)) {
                Ok(r) => out(r.is_ok(), "bletap", r),
                Err(_) => out(
                    false,
                    "bletap",
                    Err("the radio op neither completed nor errored within 45s — on macOS this is                              almost always Bluetooth permission (System Settings → Privacy & Security →                              Bluetooth) not granted to this binary"
                        .to_string()),
                ),
            }
        }
        ["address"] => out(true, "address", harness::address()),
        ["newaddress"] => out(true, "newaddress", harness::new_address()),
        ["detect"] => out(true, "detect", harness::detect()),
        ["viewseed"] => out(true, "viewseed", harness::view_seed()),
        ["balance"] => out(true, "balance", harness::balance()),
        // SPEED R5: payments on their way in — in the node's pool, not yet settled; never part of the balance.
        ["incoming"] => out(true, "incoming", harness::incoming()),
        // The Send screen's live confirmation verdict for one of this wallet's sends (by its nullifier).
        ["sendstatus", nf] => out(true, "sendstatus", harness::send_status(nf)),
        // The Activity tab's timeline (sent rows carry the live pending/confirmed status).
        ["activity"] => out(true, "activity", harness::activity()),
        // This process's send log rows (what the balance's change-in-flight figure reads).
        ["sentlog"] => out(true, "sentlog", harness::sent_log()),
        // The Testnet Tap's native drip to this wallet's own address (testnet only).
        ["faucet", usdm] => match usdm.parse::<f64>() {
            Ok(a) => out(true, "faucet", harness::faucet(a)),
            Err(e) => out(false, "faucet", Err(format!("bad amount {usdm:?}: {e}"))),
        },
        // The RECIPIENT proving settlement on its own, with no sender process alive. See harness::receipt.
        ["receipt"] => out(true, "receipt", harness::receipt()),
        ["refresh"] => out(true, "refresh", harness::refresh()),
        ["defibook", coin] => {
            let r = harness::defi_book(coin, 0.0, 0.0);
            out(r.is_ok(), "defibook", r);
        }
        ["defiprices", coin] => {
            let r = harness::defi_prices(coin, 0);
            out(r.is_ok(), "defiprices", r);
        }
        ["buysat", coin, amount, bucket] => {
            let b: usize = bucket.parse().unwrap_or(usize::MAX);
            let r = amt_then(amount, &|a| harness::buy_sat(coin, a, b));
            out(r.is_ok(), "buysat", r);
        }
        ["buysatdeposit", coin, amount, bucket] => {
            let b: usize = bucket.parse().unwrap_or(usize::MAX);
            let r = amt_then(amount, &|a| harness::buy_sat_deposit(coin, a, b));
            out(r.is_ok(), "buysatdeposit", r);
        }
        ["sellsat", coin, sat, to] => {
            let r = amt_then(sat, &|a| harness::sell_sat(coin, a, to));
            out(r.is_ok(), "sellsat", r);
        }
        // The app's default sell: the address field left empty, so Bitcoin is paid into this wallet's own vault, a fresh
        // address for every piece (Auto-OPSEC on). A command table that could only name an address could not do what a user does.
        ["sellsat", coin, sat] => {
            let r = amt_then(sat, &|a| harness::sell_sat(coin, a, ""));
            out(r.is_ok(), "sellsat", r);
        }
        ["custodykey"] => {
            let r = harness::custody_key();
            out(r.is_ok(), "custodykey", r);
        }
        ["founderkey", path] => {
            let r = harness::founder_key(path);
            out(r.is_ok(), "founderkey", r);
        }
        ["defiprogress"] => {
            let r = harness::defi_progress();
            out(r.is_ok(), "defiprogress", r);
        }
        // ⭐ EARN — the Earn screen's three actions, as the app calls them
        ["earndeposit", coin, sat] => {
            let r = amt_then(sat, &|a| harness::earn_deposit(coin, a));
            out(r.is_ok(), "earndeposit", r);
        }
        ["earnpositions"] => {
            let r = harness::earn_positions();
            out(r.is_ok(), "earnpositions", r);
        }
        ["earnwithdraw", index] => {
            let r = index.parse::<usize>().map_err(|e| format!("position index: {e}")).and_then(harness::earn_withdraw);
            out(r.is_ok(), "earnwithdraw", r);
        }
        // Debug probe: report when the scan examines the note with this cm prefix.
        ["watchcm", pfx] => out(true, "watchcm", monerousd_wallet_v2_lib::set_watch_cm(pfx)),
        // Cross-boundary check: fetch a note's DA-derived path over the real RPC and refold it here.
        // Discovery-only restore: how much does the oblivious index find WITHOUT any linear walk?
        // Report the scan cursor against the chain tip, so a driver can end a failing wait on DATA
        // instead of on a clock. See `scan_state_report`.
        ["scanstate"] => {
            let r = monerousd_wallet_v2_lib::scan_state_report();
            out(r.is_ok(), "scanstate", r);
        }
        ["olidiscover"] => {
            let r = monerousd_wallet_v2_lib::oli_discovery_report();
            out(r.is_ok(), "olidiscover", r);
        }
        ["send", to, amt] => {
            let r = amt_then(amt, &|a| harness::send(to, a));
            out(r.is_ok(), "send", r);
        }
        // ── POS (DB-307): a merchant's charge and one poll of its settle watch, the POS screen's own commands ──
        ["poscharge", amt] => {
            let r = amt_then(amt, &harness::pos_charge);
            out(r.is_ok(), "poscharge", r);
        }
        ["posawait", amt, since] => {
            let r = since
                .parse::<u64>()
                .map_err(|e| format!("bad since_height '{since}': {e}"))
                .and_then(|s| amt_then(amt, &|a| harness::pos_await(a, s)));
            out(r.is_ok(), "posawait", r);
        }
        // ── LETTER (private messenger) ──
        ["letteraddr"] => out(true, "letteraddr", harness::letter_address()),
        ["letterinbox"] => out(true, "letterinbox", harness::letter_inbox()),
        // profileset <fee_micro> <display>|<bio>  (display/bio joined+split on '|' so both may hold spaces)
        ["profileset", fee, rest @ ..] => {
            let joined = rest.join(" ");
            let (display, bio) = match joined.split_once('|') {
                Some((d, b)) => (d.trim().to_string(), b.trim().to_string()),
                None => (joined.trim().to_string(), String::new()),
            };
            let r = fee
                .parse::<u64>()
                .map_err(|e| format!("bad fee_micro '{fee}': {e}"))
                .and_then(|mu| harness::profile_set(&display, &bio, mu));
            out(r.is_ok(), "profileset", r);
        }
        ["profileget", addr] => {
            let r = harness::profile_get(addr);
            out(r.is_ok(), "profileget", r);
        }
        ["noteowned", cm] => {
            let r = harness::note_owned(cm);
            out(r.is_ok(), "noteowned", r);
        }
        ["letterhistory", from] => {
            let f: u64 = match from.parse() { Ok(v) => v, Err(_) => 0 };
            out(true, "letterhistory", harness::letter_history(f))
        }
        ["lettersend", to, rest @ ..] => {
            let msg = rest.join(" ");
            let r = harness::letter_send(to, &msg);
            out(r.is_ok(), "lettersend", r);
        }
        ["stake", amt] => {
            let r = amt_then(amt, &|a| harness::stake(a, None));
            out(r.is_ok(), "stake", r);
        }
        ["stake", amt, tier] => {
            let t = tier.parse::<u8>().ok();
            let r = amt_then(amt, &|a| harness::stake(a, t));
            out(r.is_ok(), "stake", r);
        }
        ["buy", asset, usdm] => {
            let r = usdm
                .parse::<f64>()
                .map_err(|e| format!("bad amount {usdm:?}: {e}"))
                .and_then(|a| harness::buy(asset, a));
            out(r.is_ok(), "buy", r);
        }
        ["sell", usdm, asset, to] => {
            let r = usdm
                .parse::<f64>()
                .map_err(|e| format!("bad amount {usdm:?}: {e}"))
                .and_then(|a| harness::sell(a, asset, to));
            out(r.is_ok(), "sell", r);
        }
        // The Sell screen with Auto-OPSEC turned off: paid at the next batch instead of a sealed random delay. The wallet
        // refuses it while Auto-OPSEC is on, exactly as the screen does.
        ["cashoutprogress"] => out(true, "cashoutprogress", harness::cash_out_progress()),
        ["sellfast", usdm, asset, to] => {
            let r = usdm
                .parse::<f64>()
                .map_err(|e| format!("bad amount {usdm:?}: {e}"))
                .and_then(|a| harness::sell_fast(a, asset, to));
            out(r.is_ok(), "sellfast", r);
        }
        ["mint", swap_id] => {
            let r = harness::try_mint(swap_id);
            out(r.is_ok(), "mint", r);
        }
        ["swap", swap_id] => {
            let r = harness::swap_status(swap_id);
            out(r.is_ok(), "swap", r);
        }
        ["bond", amt] => {
            let r = amt_then(amt, &|a| harness::bond(a));
            out(r.is_ok(), "bond", r);
        }
        ["claim"] => out(true, "claim", harness::claim_stake_reward()),
        ["unbond"] => out(true, "unbond", harness::unbond()),
        // §BR-3 17.5 — the repayment pot the Borrow page shows (the one wallet command no simulated wallet drove: a T0 coverage
        // surface in the hole scanner); the journey's wallet reads it beside its balance.
        ["repayment_pot"] => out(true, "repayment_pot", harness::repayment_pot()),
        ["unstake"] => {
            let r = harness::unstake();
            out(r.is_ok(), "unstake", r);
        }
        ["mystake"] => out(true, "mystake", harness::my_stake()),
        ["mybond"] => out(true, "mybond", harness::my_bond()),
        // AUTO-OPSEC: read the one privacy setting, or set it on / off
        // §BR-11 "BOND MY REWARDS": read the switch, or set it on / off (every later refresh bonds new mining rewards)
        ["bondrewards"] => {
            let r = harness::bond_rewards();
            out(r.is_ok(), "bondrewards", r);
        }
        ["bondrewards", state] => {
            let r = match *state {
                "on" => harness::set_bond_rewards(true),
                "off" => harness::set_bond_rewards(false),
                other => Err(format!("bondrewards takes on or off, not {other:?}")),
            };
            out(r.is_ok(), "bondrewards", r);
        }
        // §BR-3 17.3: delegate SAT to a validator (empty id: a seated one at random), undelegate all, release matured, list
        ["delegate", amt] => {
            let r = amt_then(amt, &|a| harness::delegate_sat(a, ""));
            out(r.is_ok(), "delegate", r);
        }
        ["delegate", amt, vid] => {
            let r = amt_then(amt, &|a| harness::delegate_sat(a, vid));
            out(r.is_ok(), "delegate", r);
        }
        ["undelegate"] => {
            let r = harness::undelegate_sat();
            out(r.is_ok(), "undelegate", r);
        }
        ["release"] => {
            let r = harness::release_sat();
            out(r.is_ok(), "release", r);
        }
        ["delegations"] => {
            let r = harness::delegations();
            out(r.is_ok(), "delegations", r);
        }
        ["autoopsec"] => {
            let r = harness::auto_opsec();
            out(r.is_ok(), "autoopsec", r);
        }
        ["autoopsec", state] => {
            let r = match *state {
                "on" => harness::set_auto_opsec(true),
                "off" => harness::set_auto_opsec(false),
                other => Err(format!("autoopsec takes on or off, not {other:?}")),
            };
            out(r.is_ok(), "autoopsec", r);
        }
        // §BR-2: a deposit's reclaim quote, and the reclaim itself (the depositor's own refund after one week)
        ["reclaimquote", swap_id] => {
            let r = harness::reclaim_deposit_quote(swap_id);
            out(r.is_ok(), "reclaimquote", r);
        }
        ["reclaim", swap_id] => {
            let r = harness::reclaim_deposit(swap_id);
            out(r.is_ok(), "reclaim", r);
        }
        // Send exactly <atomic> of an asset (symbol or 24-byte tag) — the asset transfer door; to one's own address it cuts
        // a grid lot an LP ladder can rest (`pq_ladder`: a rung needs a note of exactly its lot).
        ["assetsend", to, asset, atomic] => {
            let r = atomic.parse::<u64>().map_err(|e| format!("bad atomic amount: {e}")).and_then(|a| harness::asset_send(to, asset, a));
            out(r.is_ok(), "assetsend", r);
        }
        ["tokencreate", symbol, name, supply] => {
            out(true, "tokencreate", harness::token_create(symbol, name, supply))
        }
        ["nftcreate", symbol, name] => {
            let r = harness::nft_create(symbol, name);
            out(r.is_ok(), "nftcreate", r);
        }
        // Spec §12.6, the marketplace without the page: publish a collection (its cover read from a file, or `-` for
        // none), and create one NFT whose picture goes on the chain, filed under a collection (`-` for none). The same
        // core paths the studio's "Create the collection" runs after its dollar confirmation.
        ["collectionpublish", handle, title, cover_file] => {
            let r = (|| -> Result<serde_json::Value, String> {
                let cover = if *cover_file == "-" { Vec::new() } else { std::fs::read(cover_file).map_err(|e| format!("the cover file could not be read: {e}"))? };
                harness::collection_publish(handle, title, cover)
            })();
            out(r.is_ok(), "collectionpublish", r);
        }
        ["nftcreateart", symbol, name, art_file, collection] => {
            let r = (|| -> Result<serde_json::Value, String> {
                let art = std::fs::read(art_file).map_err(|e| format!("the picture file could not be read: {e}"))?;
                harness::nft_create_art(symbol, name, &art, if *collection == "-" { "" } else { collection })
            })();
            out(r.is_ok(), "nftcreateart", r);
        }
        // IonSwap's NFT and token pages, without the page: read a card, rest one order, quote and fill over the whole lattice.
        ["assetcard", card] => {
            let r = harness::asset_card(card);
            out(r.is_ok(), "assetcard", r);
        }
        ["orderpost", give, get, lot, pay, expires] => {
            let r = (|| -> Result<serde_json::Value, String> {
                let n = |s: &str, what: &str| s.parse::<u64>().map_err(|e| format!("bad {what}: {e}"));
                harness::order_post(give, get, n(lot, "lot")?, n(pay, "pay")?, n(expires, "expires")?)
            })();
            out(r.is_ok(), "orderpost", r);
        }
        // IonSwap pools, without the page: list (a search word, or `-` for every pool), one pool with this wallet's
        // position, and the orders. Amounts are atomic units. `poolremove <token> 0` hands back every share.
        ["poollist", q] => {
            let r = harness::pool_list(if *q == "-" { "" } else { q });
            out(r.is_ok(), "poollist", r);
        }
        ["poolinfo", token] => {
            let r = harness::pool_info(token);
            out(r.is_ok(), "poolinfo", r);
        }
        ["pooladd", token, x, y] => {
            let r = (|| -> Result<serde_json::Value, String> {
                let n = |s: &str, what: &str| s.parse::<u64>().map_err(|e| format!("bad {what}: {e}"));
                harness::pool_order(usdmd_node::ion_pool_tx::ION_ADD, token, n(x, "token amount")?, n(y, "USDm amount")?, 0, 0)
            })();
            out(r.is_ok(), "pooladd", r);
        }
        ["poolbuy", token, y, min_out] => {
            let r = (|| -> Result<serde_json::Value, String> {
                let n = |s: &str, what: &str| s.parse::<u64>().map_err(|e| format!("bad {what}: {e}"));
                harness::pool_order(usdmd_node::ion_pool_tx::ION_BUY, token, 0, n(y, "USDm amount")?, 0, n(min_out, "floor")?)
            })();
            out(r.is_ok(), "poolbuy", r);
        }
        ["poolsell", token, x, min_out] => {
            let r = (|| -> Result<serde_json::Value, String> {
                let n = |s: &str, what: &str| s.parse::<u64>().map_err(|e| format!("bad {what}: {e}"));
                harness::pool_order(usdmd_node::ion_pool_tx::ION_SELL, token, n(x, "token amount")?, 0, 0, n(min_out, "floor")?)
            })();
            out(r.is_ok(), "poolsell", r);
        }
        ["poollaunch", token, x] => {
            let r = x.parse::<u64>().map_err(|e| format!("bad token amount: {e}")).and_then(|x| harness::pool_order(usdmd_node::ion_pool_tx::ION_LAUNCH, token, x, 0, 0, 0));
            out(r.is_ok(), "poollaunch", r);
        }
        // the pool orders this run of the wallet sent, and what each was paid
        ["poolorders"] => {
            let r = harness::pool_orders();
            out(r.is_ok(), "poolorders", r);
        }
        // one token for another in one order: `poolswap <from> <to> <amount of from> <least USDm> <least of to>`
        ["poolswap", from, to, x, min_usdm, min_out] => {
            let n = |s: &str, what: &str| s.parse::<u64>().map_err(|e| format!("bad {what}: {e}"));
            let r = (|| harness::pool_swap(from, to, n(x, "token amount")?, n(min_usdm, "USDm floor")?, n(min_out, "token floor")?))();
            out(r.is_ok(), "poolswap", r);
        }
        ["poolclaim", token] => {
            let r = harness::pool_claim(token);
            out(r.is_ok(), "poolclaim", r);
        }
        ["poolremove", token, shares] => {
            let r = shares.parse::<u64>().map_err(|e| format!("bad share amount: {e}")).and_then(|s| harness::pool_remove(token, s));
            out(r.is_ok(), "poolremove", r);
        }
        // spec §14 liquidity locks, the exact core paths the shipped pages call: `poollock <token> <shares, 0 = all> <from
        // week, 0 = plain shares> <until week>`, `poolunlock <token> <shares> <week>`, `poolremovelocked <token> <shares> <week>`
        ["poollock", token, shares, from, until] => {
            let n = |s: &str, what: &str| s.parse::<u64>().map_err(|e| format!("bad {what}: {e}"));
            let w = |s: &str, what: &str| s.parse::<u32>().map_err(|e| format!("bad {what}: {e}"));
            let r = (|| harness::pool_lock(token, n(shares, "share amount")?, w(from, "from week")?, w(until, "until week")?))();
            out(r.is_ok(), "poollock", r);
        }
        ["poolunlock", token, shares, week] => {
            let r = (|| harness::pool_unlock(token, shares.parse::<u64>().map_err(|e| format!("bad share amount: {e}"))?, week.parse::<u32>().map_err(|e| format!("bad week: {e}"))?))();
            out(r.is_ok(), "poolunlock", r);
        }
        ["poolremovelocked", token, shares, week] => {
            let r = (|| harness::pool_remove_locked(token, shares.parse::<u64>().map_err(|e| format!("bad share amount: {e}"))?, week.parse::<u32>().map_err(|e| format!("bad week: {e}"))?))();
            out(r.is_ok(), "poolremovelocked", r);
        }
        ["swapquoteall", base, quote, budget] => {
            let r = budget.parse::<u64>().map_err(|e| format!("bad budget: {e}")).and_then(|b| harness::swap_quote_all(base, quote, b));
            out(r.is_ok(), "swapquoteall", r);
        }
        ["swapexecall", base, quote, budget, min_out] => {
            let r = budget
                .parse::<u64>()
                .map_err(|e| format!("bad budget: {e}"))
                .and_then(|b| min_out.parse::<u64>().map_err(|e| format!("bad min_out: {e}")).map(|m| (b, m)))
                .and_then(|(b, m)| harness::swap_execute_all(base, quote, b, m));
            out(r.is_ok(), "swapexecall", r);
        }
        // §BR-12 F13: the publisher's deploy and the caller's paid call, the exact core paths the shipped UI runs.
        ["dsoldeploy", code_hex, height, name, fee] => {
            let r = height
                .parse::<u64>()
                .map_err(|e| format!("bad height class: {e}"))
                .and_then(|h| fee.parse::<f64>().map_err(|e| format!("bad fee: {e}")).map(|f| (h, f)))
                .and_then(|(h, f)| harness::dsol_deploy(code_hex, h, name, f));
            out(r.is_ok(), "dsoldeploy", r);
        }
        ["dsolcall", params] => {
            let r = serde_json::from_str::<serde_json::Value>(params).map_err(|e| format!("bad params: {e}")).and_then(harness::dsol_call);
            out(r.is_ok(), "dsolcall", r);
        }
        // DEX: rest a REAL LP ladder on this wallet's node — the exact page path. The gate uses
        // this to prove an order posted on node A appears on node B's book (mesh gossip).
        // `lot` is a literal atomic amount, or `auto` = the wallet's own largest owned lot
        // (resolved inside the wallet — holdings never cross this pipe).
        ["ladderpost", base, quote, lot, mid, step, rungs, expires] => {
            let parsed = (|| -> Result<(Option<u64>, u64, u64, u32, u64), String> {
                let lot = if *lot == "auto" {
                    None
                } else {
                    Some(lot.parse().map_err(|e| format!("bad lot: {e}"))?)
                };
                Ok((
                    lot,
                    mid.parse().map_err(|e| format!("bad mid: {e}"))?,
                    step.parse().map_err(|e| format!("bad step: {e}"))?,
                    rungs.parse().map_err(|e| format!("bad rungs: {e}"))?,
                    expires.parse().map_err(|e| format!("bad expires: {e}"))?,
                ))
            })();
            let res = parsed.and_then(|(l, m, s, r, x)| {
                harness::ladder_post(base, quote, l, m, s, r, x)
            });
            out(res.is_ok(), "ladderpost", res);
        }
        // DEX TAKER: fill against the resting book (the Swap screen's own execute path).
        ["swapexec", base, quote, budget, min_out] => {
            let res = budget
                .parse::<u64>()
                .map_err(|e| format!("bad budget: {e}"))
                .and_then(|b| min_out.parse::<u64>().map_err(|e| format!("bad min_out: {e}")).map(|m| (b, m)))
                .and_then(|(b, m)| harness::swap_execute(base, quote, b, m));
            out(res.is_ok(), "swapexec", res);
        }
        // DEX: read one book level from this wallet's OWN node (the swap-quote read path).
        ["booklevel", base, quote, level] => {
            let res = level
                .parse::<u64>()
                .map_err(|e| format!("bad level: {e}"))
                .and_then(|l| harness::book_level(base, quote, l));
            out(res.is_ok(), "booklevel", res);
        }
        ["username", name] => out(true, "username", harness::register_username(name)),
        ["resolve", name] => out(true, "resolve", harness::resolve_username(name)),
        ["myname"] => {
            let r = harness::my_username();
            out(r.is_ok(), "myname", r);
        }
        // ⭐ `ble_tap_pay`'s JOIN over any carrier: the tap's four protocol steps (`moneropay_ble::tap_*`), each
        // side's frames handed to the driver, which relays them to the OTHER process — the two devices share
        // nothing else. The payment itself is then an ordinary `send` of the opened charge in this session.
        // DB-319: the merchant presents the ONE signed charge (`wallet_pos_charge`'s builder) — never a second,
        // unsigned shape; the payer opens it to the VERIFIED view and pays through the ONE pay path (`tappay`).
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["tapcharge-begin", atomic] => {
            let res = atomic.parse::<u64>().map_err(|e| format!("bad atomic amount: {e}")).and_then(|a| {
                let charge = serde_json::to_vec(&harness::pos_charge_atomic(a)?)
                    .map_err(|e| format!("charge encode: {e}"))?;
                let (m, frames) = monerousd_wallet_v2_lib::moneropay_ble::tap_merchant_begin(charge)?;
                *TAP_MERCHANT.lock().map_err(|_| "tap state lock poisoned".to_string())? = Some(m);
                Ok(frames_json(&frames))
            });
            out(res.is_ok(), "tapcharge-begin", res);
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["tapcharge-encaps", frames] => {
            let res = frames_arg(frames).and_then(|f| {
                let (p, out) = monerousd_wallet_v2_lib::moneropay_ble::tap_payer_encaps(&f)?;
                *TAP_PAYER.lock().map_err(|_| "tap state lock poisoned".to_string())? = Some(p);
                Ok(frames_json(&out))
            });
            out(res.is_ok(), "tapcharge-encaps", res);
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["tapcharge-seal", frames] => {
            let res = frames_arg(frames).and_then(|f| {
                let m = TAP_MERCHANT
                    .lock()
                    .map_err(|_| "tap state lock poisoned".to_string())?
                    .take()
                    .ok_or_else(|| "no tap in progress on this merchant (tapcharge-begin first)".to_string())?;
                Ok(frames_json(&monerousd_wallet_v2_lib::moneropay_ble::tap_merchant_seal(&m, &f)?))
            });
            out(res.is_ok(), "tapcharge-seal", res);
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))] // the Bluetooth tap exists only where moneropay_ble does
        ["tapcharge-open", frames] => {
            let res = frames_arg(frames).and_then(|f| {
                let p = TAP_PAYER
                    .lock()
                    .map_err(|_| "tap state lock poisoned".to_string())?
                    .take()
                    .ok_or_else(|| "no tap in progress on this payer (tapcharge-encaps first)".to_string())?;
                let charge = monerousd_wallet_v2_lib::moneropay_ble::tap_payer_open(&p, &f)?;
                let parsed: serde_json::Value = serde_json::from_slice(&charge)
                    .map_err(|e| format!("the opened charge is not JSON ({e})"))?;
                // The payer's gate, exactly as the tap UI runs it: signature, key↔address bind, expiry, and the
                // shown amount == the signed amount. What it returns is what `tappay` will send.
                let v = harness::pos_verify(parsed)?;
                let to = v.get("to").and_then(|x| x.as_str()).ok_or("the verified charge names no recipient")?;
                let atomic = v.get("amount_atomic").and_then(|x| x.as_u64()).ok_or("the verified charge names no amount")?;
                // The opened charge as ONE whitespace-free token, so the payment can run in whichever session pays.
                Ok(serde_json::json!({
                    "to": to, "atomic": atomic, "usdm": atomic as f64 / 100_000_000.0, "charge_hex": hex::encode(&charge)
                }))
            });
            out(res.is_ok(), "tapcharge-open", res);
        }
        // DB-319: PAY an opened charge through the ONE path that moves a tap's money (`wallet_pos_pay`: the gate
        // again, then exactly the signed atomic amount) — the step the tap UI runs after its verify.
        ["tappay", charge_hex] => {
            let res = hex::decode(charge_hex)
                .map_err(|e| format!("bad charge hex: {e}"))
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| format!("charge JSON: {e}")))
                .and_then(harness::pos_pay);
            out(res.is_ok(), "tappay", res);
        }
        _ => out(false, "unknown", Err(format!("unknown command: {line}"))),
    }
}

fn main() {
    // ⛔⛔⛔ THE HARNESS IS ATTACH-ONLY. It reads, detects and sends against nodes OTHER supervisors own
    // (launchd / the operator). MEASURED 2026-08-19: without this, the wallet lib's in-process node
    // watchdog fired during slow probes and REPLACED the machine's node service definition mid-boot —
    // the silent node deaths and the every-20s boot-kill churn that halted the chain. The harness must
    // never spawn, install, or bounce a node.
    std::env::set_var("MONEROUSD_WALLET_ATTACH_ONLY", "1");
    // ONE-SHOT (app-bundle) mode: `… MUSDHarness.app --args <config.json>`. See `run_oneshot`.
    if let Some(cfg) = std::env::args().nth(1) {
        if cfg.ends_with(".json") {
            run_oneshot(&cfg);
        }
    }
    // Open the ONE real wallet for this process: from its 24-word seed (HARNESS_SEED — the exact restore path the
    // app uses), or FRESH via HARNESS_GENERATE=1 (the exact create path the app uses: birth at the current tip,
    // scan starts there — like tapping "Create wallet"). The generate result carries the new seed + address.
    if std::env::var("HARNESS_GENERATE").ok().as_deref() == Some("1") {
        match harness::generate() {
            Ok(v) => emit(true, "generate", Ok(v)),
            Err(e) => {
                emit(false, "generate", Err(e));
                std::process::exit(2);
            }
        }
    } else {
        // HARNESS_SEED_STDIN=1 (the `musd` command line): the phrase is the first line on stdin, so it never sits in this
        // process's environment, where any program run by the same user can read it.
        let seed = if std::env::var("HARNESS_SEED_STDIN").ok().as_deref() == Some("1") {
            let mut first = String::new();
            if std::io::stdin().lock().read_line(&mut first).is_err() || first.trim().is_empty() {
                emit(false, "restore", Err("the recovery phrase did not arrive on the first line of input".to_string()));
                std::process::exit(2);
            }
            first
        } else {
            std::env::var("HARNESS_SEED").expect("HARNESS_SEED (24-word recovery phrase) is required")
        };
        match harness::restore(seed.trim()) {
            Ok(v) => emit(true, "restore", Ok(v)),
            Err(e) => {
                emit(false, "restore", Err(e));
                std::process::exit(2); // cannot even open the wallet — hard fail (no wallet, no test)
            }
        }
    }

    let stdin = std::io::stdin();
    // ⛔⛔⛔ SAY WHY THIS PROCESS ENDED, OR A WALLET DEATH READS AS A CHAIN FAILURE.
    //
    // The driver parses every reply as JSON. When this process exits, its next `read_line` returns EOF —
    // an EMPTY string — and the driver panics at its reply parser with a serde error, which looks identical
    // to a malformed reply and NOTHING like "the wallet went away". MEASURED 2026-08-09: a cross-device run
    // failed at `cross_device_send.rs:221` (the reply parser) with the payer's last log line being a
    // SUCCESSFUL send and no panic in either wallet — a wallet-process death that was being counted as a
    // failed payment. Those are opposite defects and they need opposite fixes.
    //
    // So name the exit on stderr, which the driver captures to `wallet.stderr`. This changes no protocol
    // byte on stdout.
    let mut _cmds_served: u64 = 0;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "[harness-exit] stdin read FAILED ({e}) — this process is ending, so the driver's next \
                     reply is EOF and will surface as a malformed-JSON panic. That is a WALLET DEATH, not a \
                     failed payment."
                );
                break;
            }
        };
        let line = line.trim();
        // ⭐⭐⭐ NAME THE COMMAND IN FLIGHT — A KILLED PROCESS LEAVES NO OTHER TRACE.
        //
        // MEASURED 2026-08-10: the payer's stderr ended at a SUCCESSFUL `[wallet_send] ... node status OK`
        // with NO `[harness-exit]` line of either kind — so this process neither ended its input normally nor
        // failed a stdin read. It was KILLED (no unwind, no panic). The driver then read EOF and panicked at
        // its JSON reply parser, and I counted that as a failed payment three runs running. It was not: the
        // chain did its job and the wallet process died afterwards.
        //
        // `_cmds_served` was also never incremented, so the exit line it feeds would have reported 0 commands
        // no matter how many ran — a counter that cannot count, which is the same class as the probes that
        // could not fail. Both fixed here: count every command, and echo it BEFORE serving it so the last
        // line in the log is the operation that was in flight when the process went away.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: the command VERB only (`send`, `holdings`, `address`), never its
        // arguments — no address, amount, key or commitment reaches this line. Goes to stderr, so it changes
        // no protocol byte on stdout.
        if !line.is_empty() {
            _cmds_served = _cmds_served.saturating_add(1);
            let verb = line.split_whitespace().next().unwrap_or("(empty)");
            eprintln!("[harness-cmd] #{_cmds_served} serving `{verb}` — if this is the last line, the process died HERE");
        }
        if line.is_empty() {
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }
        serve(line, &mut |ok, op, r| emit(ok, op, r));
    }

    // A CLEAN end of input is the other way the driver sees EOF. Announce it for the same reason: silence
    // here is indistinguishable from a crash, and both surface as one unexplained JSON parse error.
    eprintln!("[harness-exit] stdin closed after {_cmds_served} command(s) — normal end of input.");
}
