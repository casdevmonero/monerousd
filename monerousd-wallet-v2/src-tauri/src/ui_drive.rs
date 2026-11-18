// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// ⭐ THE UI DRIVER (R7): drives the SHIPPED front end (`../dist`) in headless Chromium through `../ui-pins/driver.mjs`, with
// every `invoke` dispatched through `tauri::test`'s mock runtime into the real wallet core (`wallet_invoke_handler!()`).
// LAYER 1 (`ui_pins`, tests): no node — a value-moving command is recorded at the core's door and refused, never run.
// LAYER 2 (the `ui-harness` binary, `--features ui-harness`): the core talks to a REAL node the simulator serves, and a
// value-moving command RUNS (the `unattended-test` build compiles the biometric prompt out), so a flow's effect is asserted
// on the node and its peer by the simulator that spawned the harness.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

/// A flow's verdict as the driver reported it, plus what the harness itself saw on the wire.
pub struct FlowRun {
    pub report: serde_json::Value,
    pub invoked: Vec<String>,
}

impl FlowRun {
    pub fn ok(&self) -> bool {
        self.report.get("ok").and_then(|v| v.as_bool()) == Some(true)
    }
    /// The names of the steps the driver reported as failed (a report with no step list fails as `<no steps>`).
    pub fn failed_steps(&self) -> Vec<String> {
        let Some(steps) = self.report.get("steps").and_then(|s| s.as_array()) else {
            return vec!["<no steps>".into()];
        };
        steps
            .iter()
            .filter(|s| s.get("ok").and_then(|v| v.as_bool()) != Some(true))
            .map(|s| match s.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => format!("<unnamed step {s}>"),
            })
            .collect()
    }
}

/// A core answer rewritten before the page sees it — the planted defect a harness must catch.
pub type Tamper = fn(&str, &mut serde_json::Value);

/// The wallet core is process-global (`WALLET`, the note store), so flows run one at a time.
pub static FLOW_LOCK: Mutex<()> = Mutex::new(());
/// The real HOME, captured before the harness isolates it (the driver finds its browser under it).
pub static REAL_HOME: OnceLock<String> = OnceLock::new();

/// Isolate the core from this machine once per process: a fresh per-process data dir and HOME (the core creates them;
/// the seed file and note store never touch the user's real wallet), and a node URL on a closed loopback port (no node —
/// LAYER 1).
pub fn isolate_core() {
    isolate_core_with_node(None);
}

/// [`isolate_core`] with the node the core talks to: `None` = a closed loopback port (LAYER 1), `Some(url)` = a real node
/// (LAYER 2).
pub fn isolate_core_with_node(node_url: Option<&str>) {
    REAL_HOME.get_or_init(|| {
        let home = std::env::var("HOME").expect("HOME names the user's home (the driver's browser cache lives under it)");
        let dir = std::env::temp_dir().join(format!("ui-pins-{}", std::process::id()));
        let url = match node_url {
            Some(u) => u.to_string(),
            None => {
                let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
                let port = closed.local_addr().expect("its port").port();
                drop(closed);
                format!("http://127.0.0.1:{port}")
            }
        };
        std::env::set_var("MONEROUSD_WALLET_DATA", &dir);
        std::env::set_var("HOME", &dir);
        std::env::set_var("MONEROUSD_NODE_URL", url);
        home
    });
}

pub fn wallet_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("monerousd-wallet-v2").to_path_buf()
}

/// `playwright-core`: `MONEROUSD_PLAYWRIGHT_CORE`, else the nearest `monerousd-ide/node_modules/playwright-core` above
/// this crate. Missing is a FAILURE with its cause, never a skip.
pub fn playwright_core() -> PathBuf {
    if let Ok(p) = std::env::var("MONEROUSD_PLAYWRIGHT_CORE") {
        return PathBuf::from(p);
    }
    let mut d = Some(wallet_root());
    while let Some(dir) = d {
        let c = dir.join("monerousd-ide/node_modules/playwright-core");
        if c.join("package.json").is_file() {
            return c;
        }
        d = dir.parent().map(Path::to_path_buf);
    }
    panic!("playwright-core not found: set MONEROUSD_PLAYWRIGHT_CORE or install it under monerousd-ide/node_modules");
}

/// Answer one `invoke` through the shipped command list, as the desktop app's IPC would. An answer that is not JSON is
/// an error the page sees, never a null.
pub fn dispatch(
    wv: &tauri::WebviewWindow<tauri::test::MockRuntime>,
    cmd: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Value> {
    let req = tauri::webview::InvokeRequest {
        cmd: cmd.into(),
        callback: tauri::ipc::CallbackFn(0),
        error: tauri::ipc::CallbackFn(1),
        url: "tauri://localhost".parse().expect("the app origin"),
        body: tauri::ipc::InvokeBody::Json(args),
        headers: Default::default(),
        invoke_key: tauri::test::INVOKE_KEY.to_string(),
    };
    let body = tauri::test::get_ipc_response(wv, req)?;
    body.deserialize::<serde_json::Value>()
        .map_err(|e| serde_json::Value::String(format!("UI_PIN: {cmd} answered a body that is not JSON: {e}")))
}

/// Drive one flow of `../ui-pins/driver.mjs` against the real core; `tamper` plants a defect in the core's answers.
pub fn drive(flow: &str, tamper: Option<Tamper>) -> FlowRun {
    drive_with(flow, tamper, None)
}

/// `drive` with `plant` naming a defect the driver plants in the served `app.js` (its `PLANTS`).
///
/// A value-moving command is recorded at the core's door and answered with a refusal, never run: the shipped core asks
/// for Touch ID before it moves value, and a harness must not raise the Mac's real system prompt. The claim these flows
/// make is what the page did BEFORE the core was asked, so the record at the door is the whole evidence.
pub fn drive_with(flow: &str, tamper: Option<Tamper>, plant: Option<&str>) -> FlowRun {
    drive_mode(flow, tamper, plant, false)
}

/// ⭐ LAYER 2: drive `flow` against the node the core was isolated to, RUNNING every value-moving command (the simulator
/// asserts its effect on the node and its peer).
pub fn drive_live(flow: &str) -> FlowRun {
    drive_mode(flow, None, None, true)
}

fn drive_mode(flow: &str, tamper: Option<Tamper>, plant: Option<&str>, live: bool) -> FlowRun {
    let _one = FLOW_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !live {
        isolate_core();
    }
    let app = crate::ui_pin_app();
    let wv = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("the mock main webview");

    let root = wallet_root();
    let mut child = Command::new("node")
        .arg(root.join("ui-pins/driver.mjs"))
        .env("HOME", REAL_HOME.get().expect("captured"))
        .env("UI_PIN_DIST", root.join("dist"))
        .env("UI_PIN_FLOW", flow)
        .env("UI_PIN_PLAYWRIGHT", playwright_core())
        .env("UI_PIN_VALUE_MOVING", VALUE_MOVING.join(","))
        .env("UI_PIN_PLANT", plant.unwrap_or(""))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("node runs the UI driver");
    let stdin = Arc::new(Mutex::new(child.stdin.take().expect("driver stdin")));
    let stdout = BufReader::new(child.stdout.take().expect("driver stdout"));
    if live {
        // WEBSITE CONNECT: the door's events reach the shipped wallet page as the app's own events do (the driver hands
        // each `{t:"event"}` line to the page's listeners), so a website's request crosses the REAL door, the REAL
        // core and the REAL page.
        let pipe = Arc::clone(&stdin);
        crate::web3_bridge::set_emitter(move |name, payload| {
            let line = serde_json::json!({ "t": "event", "name": name, "payload": payload });
            if let Ok(mut w) = pipe.lock() {
                let _ = writeln!(w, "{line}").and_then(|_| w.flush());
            }
        });
        crate::web3_bridge::set_private_reader(crate::web3_private_read);
    }
    let invoked = Arc::new(Mutex::new(Vec::new()));
    let mut report = serde_json::json!({ "ok": false, "error": "the driver exited without a verdict" });
    for line in stdout.lines() {
        let line = line.expect("driver stdout line");
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
            eprintln!("[ui-driver] {line}");
            continue;
        };
        match msg.get("t").and_then(|t| t.as_str()) {
            Some("invoke") => {
                let id = msg["id"].clone();
                let cmd = msg["cmd"].as_str().expect("an invoke names its command").to_string();
                let args = msg["args"].clone();
                invoked.lock().expect("the invoke log").push(cmd.clone());
                let (wv, stdin) = (wv.clone(), Arc::clone(&stdin));
                // The page fires invokes concurrently, as the desktop IPC lets it; each answer is tagged with its id.
                std::thread::spawn(move || {
                    let answer = if !live && VALUE_MOVING.contains(&cmd.as_str()) {
                        Err(serde_json::Value::String(format!("UI_PIN: {cmd} reached the core's door (recorded, not run)")))
                    } else {
                        dispatch(&wv, &cmd, args)
                    };
                    // LAYER 2: a value-moving command's REAL answer goes to the simulator at once (it reads, e.g., a send's
                    // recipient commitment to assert the peer holds it)
                    if live && VALUE_MOVING.contains(&cmd.as_str()) {
                        let v = match &answer {
                            Ok(v) => v.clone(),
                            Err(e) => serde_json::json!({ "error": e }),
                        };
                        println!("{}", serde_json::json!({ "t": "core", "cmd": cmd, "value": v }));
                    }
                    let ans = match answer {
                        Ok(mut v) => {
                            if let Some(t) = tamper {
                                t(&cmd, &mut v);
                            }
                            serde_json::json!({ "id": id, "ok": true, "value": v })
                        }
                        Err(e) => serde_json::json!({ "id": id, "ok": false, "value": e }),
                    };
                    let mut w = stdin.lock().expect("the driver pipe");
                    // A closed pipe means the driver already reported; its verdict stands.
                    if writeln!(w, "{ans}").and_then(|_| w.flush()).is_err() {
                        eprintln!("[ui-pins] the driver closed before the answer to {cmd}");
                    }
                });
            }
            Some("result") => {
                report = msg;
                break;
            }
            // LAYER 2: a live event from the flow (e.g. the wallet's address, for the simulator to fund) — forwarded at once
            Some("emit") if live => println!("{line}"),
            _ => eprintln!("[ui-driver] {line}"),
        }
    }
    drop(stdin);
    let status = child.wait().expect("the driver exits");
    let invoked = invoked.lock().expect("the invoke log").clone();
    eprintln!("[ui-pins] {flow} (driver {status}): {report}");
    FlowRun { report, invoked }
}


/// The commands that move value: each one the shipped UI calls must sit behind a confirmation the user sees first.
pub const VALUE_MOVING: [&str; 28] = [
    "wallet_send",
    // §BR-2: the depositor's own refund of a week-old deposit — it ends the swap, behind the same dollar confirmation
    "wallet_reclaim_deposit",
    // §BR-1: the cash-out burns one USDm piece per payout piece — behind the same dollar confirmation
    "wallet_cash_out",
    "wallet_send_sat",
    "wallet_stake",
    "wallet_claim_stake_reward",
    // §BR-3 17.6: unstaking returns the principal and its reward — behind the same confirmation
    "wallet_unstake",
    "wallet_bond_sat",
    // §BR-11 "Bond my rewards": switching it on consents to every later reward bond — behind the same confirmation
    "wallet_set_bond_rewards",
    // §BR-8 "Take my rewards in Bitcoin": switching it on consents to every later reward cash-out — behind the same confirmation
    "wallet_set_rewards_in_btc",
    // §BR-8 B8-b: the remixer moves the vault's Bitcoin through rounds — behind the same confirmation
    "wallet_set_remix",
    // §BR-3 17.5 layer 1: buying SAT from the repayment pot burns USDm — behind the same dollar confirmation
    "wallet_pot_buy",
    // §BR-15 Buy SAT: a sealed order burns USDm; a Bitcoin/Monero buy consents to the order its deposit's USDm places — each
    // behind the dollar confirmation naming the quote at the last price and the batch-price risk
    "wallet_buy_sat",
    "wallet_buy_sat_deposit",
    "wallet_buy_sat_private_btc",
    "wallet_sell_sat",
    // §BR-4: opening a loan and repaying it — each behind the dollar confirmation naming the liquidation price and the fees
    "wallet_borrow_open",
    "wallet_borrow_close",
    "wallet_unbond",
    // §BR-3 17.3: delegating and undelegating SAT — each behind the dollar confirmation naming the unbonding and the slash risk
    "wallet_delegate_sat",
    "wallet_undelegate_sat",
    // §22 4: "Become a validator" bonds the largest SAT note — behind the one-screen confirmation naming the fee and the slashes
    "wallet_become_validator",
    // §BR-12: a @username owes its yearly interface fee — behind the same dollar confirmation
    "wallet_register_username",
    "wallet_buy_swap",
    "wallet_pos_pay",
    "dapp_provider_transfer",
    "dapp_provider_swap_execute",
    // §BR-12 F13: a launchpad app's DSOL call pays the publisher fee — behind the dollar confirmation naming that fee
    "dapp_provider_dsol_call",
];

