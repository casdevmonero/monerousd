// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// ⭐ R7 LAYER 2 — THE UI HARNESS: one process, one wallet core, the SHIPPED front end driven headless through one flow of
// `../ui-pins/driver.mjs` against the node at `--node <url>` (a simulated node's production RPC), with every value-moving
// command RUN. The simulator spawns it (as it spawns `wallet-harness`) and asserts the flow's effect on the node and its
// peer; this process prints one JSON line — `{"ok", "steps", "invoked", ...}` — and exits 0 when the driver's steps passed.
// Built only with `--features ui-harness` (DEV/TEST ONLY).

fn main() {
    let mut flow = None;
    let mut node = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--flow" => flow = args.next(),
            "--node" => node = args.next(),
            _ => {}
        }
    }
    let (Some(flow), Some(node)) = (flow, node) else {
        eprintln!("usage: ui-harness --flow <name> --node <http://127.0.0.1:port>");
        std::process::exit(2);
    };
    monerousd_wallet_v2_lib::ui_drive::isolate_core_with_node(Some(&node));
    let run = monerousd_wallet_v2_lib::ui_drive::drive_live(&flow);
    let mut out = run.report.clone();
    out["invoked"] = serde_json::json!(run.invoked);
    println!("{out}");
    std::process::exit(if run.ok() { 0 } else { 1 });
}
