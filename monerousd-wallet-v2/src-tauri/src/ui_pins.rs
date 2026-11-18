// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// ⭐ THE UI PIN HARNESS (§PRODUCT, R7 — user 2026-10-26: "ready for real funds should mean the entire ecosystem is built out
// both front end and backend"). A flow pin drives the SHIPPED front end (`../dist`, byte for byte what the app bundles) in
// headless Chromium and asserts what the REAL wallet core holds afterwards — never what a call returned to the page.
//
// Shape (borrowed, not re-derived): Playwright drives the web build (`../ui-pins/driver.mjs`); its `window.__TAURI__.core.
// invoke` forwards every command over the driver's stdio to THIS process, which dispatches it through `tauri::test`'s
// mock runtime into `wallet_invoke_handler!()` — the exact command list `run()` registers, with the desktop app's own
// camelCase argument binding. Tauri's WebDriver does not run on macOS, so the webview is Chromium; everything behind
// `invoke` is the shipped core.
//
// What the harness asserts beside each flow's own steps: the page made ZERO requests outside its own origin (a wallet
// screen that fetches anything is a metadata leak), and no uncaught page error fired.
//
// LAYER 1 (this file): no node — `MONEROUSD_NODE_URL` names a closed loopback port, so a node probe fails fast and the
// flows that need no chain (create, restore, address) run on the real core. LAYER 2: an in-process simulated mesh
// behind `node_rpc`, so send/receive flows assert what the PEER node holds.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use crate::ui_drive::*;

/// The commands `wallet_invoke_handler!` registers, read from its one definition.
fn registered_commands() -> Vec<String> {
    let src = include_str!("lib.rs");
    let start = src.find("macro_rules! wallet_invoke_handler").expect("the shared command list");
    let body = &src[start..];
    let open = body.find("generate_handler![").expect("its generate_handler!") + "generate_handler![".len();
    let close = open + body[open..].find(']').expect("the list closes");
    body[open..close].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Every command name the shipped front end invokes by name (`walletCore('…')`, `_tauriInvoke('…')`, `invoke('…')`).
fn invoked_by_the_ui() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let dist = wallet_root().join("dist");
    let mut files = vec![dist.join("app.js")];
    for sub in ["lib", "pages"] {
        for e in std::fs::read_dir(dist.join(sub)).expect("a shipped script dir").flatten() {
            if e.path().extension().and_then(|x| x.to_str()) == Some("js") {
                files.push(e.path());
            }
        }
    }
    for f in files {
        let src = std::fs::read_to_string(&f).expect("a shipped script");
        let file = f.file_name().expect("a file name").to_string_lossy().into_owned();
        for call in ["walletCore(", "_tauriInvoke(", "invoke("] {
            for (i, _) in src.match_indices(call) {
                let Some(q) = src[i + call.len()..].trim_start().strip_prefix('\'') else { continue };
                let Some(end) = q.find('\'') else { continue };
                let name = &q[..end];
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()) {
                    out.push((name.to_string(), file.clone()));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// ⭐ NO DEAD BUTTON: every command the shipped UI invokes by name is one `run()` registers — a name the list lacks is a
/// button that fails on every click in the desktop app. Seconds, no browser.
#[test]
fn every_command_the_shipped_ui_invokes_is_registered() {
    let reg = registered_commands();
    assert!(reg.len() > 50, "the shared list parsed ({} names)", reg.len());
    let ui = invoked_by_the_ui();
    assert!(ui.len() > 50, "the UI census found its calls ({} names)", ui.len());
    let dead: Vec<_> = ui.iter().filter(|(n, _)| !reg.contains(n)).collect();
    assert!(dead.is_empty(), "the shipped UI invokes commands no build registers: {dead:?}");
}

/// ⭐ HARNESS PROOF on the create flow (F1's front half): Create → Generate shows a 24-word phrase drawn by the REAL core
/// → "I've written it down" opens Home → the Receive view shows the address the CORE holds for the open wallet.
#[test]
fn the_shipped_create_screen_opens_a_real_wallet_whose_address_the_core_holds() {
    let run = drive("create_opens_home", None);
    assert!(run.ok(), "the create flow on the shipped UI: failed steps {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_generate"), "the seed came from the core: {:?}", run.invoked);
    // The screen's address against what the core holds NOW (asked after the flow, outside the page).
    let shown = run.report["address_shown"].as_str().expect("the driver read the Receive screen's address").to_string();
    let held = crate::wallet_address().expect("the core has an open wallet");
    let held = held["address"].as_str().expect("the core names its address").to_string();
    assert!(!held.is_empty() && shown == held, "the Receive screen shows the core's address (shown {shown:.24}…, held {held:.24}…)");
}

/// ⭐ THE HARNESS FAILS ON A PLANTED DEFECT (B1 shape: an instrument is proven on a defect before it is trusted): the core's
/// phrase loses its last word before the page sees it — the flow must fail at the phrase step, not pass.
#[test]
fn the_ui_harness_fails_when_the_core_answer_is_tampered() {
    fn drop_last_word(cmd: &str, v: &mut serde_json::Value) {
        if cmd != "wallet_generate" {
            return;
        }
        let seed = v["seed"].as_str().expect("wallet_generate answers a seed").to_string();
        let (kept, _last) = seed.rsplit_once(' ').expect("a multi-word phrase");
        v["seed"] = serde_json::Value::String(kept.to_string());
    }
    let run = drive("create_opens_home", Some(drop_last_word));
    assert!(!run.ok(), "a 23-word phrase must fail the flow: {}", run.report);
    assert_eq!(run.failed_steps(), vec!["the phrase shown has 24 words".to_string()], "{}", run.report);
}

/// Every call site of a value-moving command in the shipped scripts, with the text of its enclosing scope (the nearest
/// `function` or `case '…'` arm above it) up to the call — what the page runs before the value moves.
fn value_moving_call_sites() -> Vec<(String, String, String)> {
    let dist = wallet_root().join("dist");
    let mut files = vec![dist.join("app.js")];
    for sub in ["lib", "pages"] {
        for e in std::fs::read_dir(dist.join(sub)).expect("a shipped script dir").flatten() {
            if e.path().extension().and_then(|x| x.to_str()) == Some("js") {
                files.push(e.path());
            }
        }
    }
    let mut out = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).expect("a shipped script");
        let file = f.file_name().expect("a file name").to_string_lossy().into_owned();
        for cmd in VALUE_MOVING {
            let quoted = format!("'{cmd}'");
            for (i, _) in src.match_indices(&quoted) {
                let before = &src[..i];
                let is_call = ["walletCore(", "_tauriInvoke(", "invoke("].iter().any(|c| before.trim_end().ends_with(c));
                if !is_call {
                    continue;
                }
                let scope = ["\nasync function ", "\nfunction ", "case '"]
                    .iter()
                    .filter_map(|m| before.rfind(m))
                    .max()
                    .expect("a call site sits inside a function or a case arm");
                out.push((cmd.to_string(), file.clone(), before[scope..].to_string()));
            }
        }
    }
    out
}

/// ⭐ A2 + A3 STATIC CENSUS (ADOPTABLE, user 2026-10-24: "every cost is shown in dollars before the user acts … no action
/// can lose funds without a plain-language warning first"): every call site of a value-moving command in the shipped UI
/// awaits the ONE shared confirmation (`confirmCost({ … usd …, warning … })`) in its own scope before the call. A site
/// with no confirmation is a button that moves value on press with no dollar cost and no warning shown. The census's
/// universe is every value-moving command the UI can call; the driven census (A2/A3 rows) proves the dialog the helper
/// draws shows the dollars.
#[test]
fn every_value_moving_call_in_the_shipped_ui_awaits_a_dollar_confirmation_with_a_warning() {
    let sites = value_moving_call_sites();
    let called: std::collections::BTreeSet<_> = sites.iter().map(|(c, _, _)| c.as_str()).collect();
    assert_eq!(called.len(), VALUE_MOVING.len(), "the census found a call site of every value-moving command: {called:?}");
    let bare: Vec<String> = sites
        .iter()
        .filter(|(_, _, scope)| {
            let Some(at) = scope.rfind("await confirmCost(") else { return true };
            let args = &scope[at..];
            !(args.contains("usd") && args.contains("warning"))
        })
        .map(|(cmd, file, scope)| format!("{file}: {cmd} in `{}`", scope.trim_start().lines().next().expect("a scope has its first line").trim()))
        .collect();
    assert!(bare.is_empty(), "{} of {} value-moving call sites move value with no dollar confirmation + warning first: {bare:#?}", bare.len(), sites.len());
}

/// ⭐ A2 + A3 DRIVEN CENSUS on the shipped UI: sell, SAT send, bond and unbond pressed as a user presses them. Every press
/// opens the ONE confirmation before the core is asked; it shows the dollars ($5.00 for a 5 USDm sale; a plain "no
/// dollar price" for SAT, with the fee in dollars) and a warning naming the lock, slashing or finality; Cancel and Escape
/// ask the core for nothing; every value-moving invoke follows a click inside a dialog showing a dollar figure.
#[test]
fn every_value_moving_press_in_the_shipped_ui_shows_its_dollars_and_warning_before_the_core_is_asked() {
    let run = drive("value_moving_presses", None);
    assert!(run.ok(), "the value-moving presses on the shipped UI: failed steps {:?} — {}", run.failed_steps(), run.report);
    for cmd in ["wallet_send_sat", "wallet_bond_sat"] {
        assert_eq!(run.invoked.iter().filter(|c| *c == cmd).count(), 1, "{cmd} reached the core once, after its Confirm: {:?}", run.invoked);
    }
    // no node here, so no chain mark: the sale shows no dollars it does not have. The priced sale is measured on a chain that
    // publishes marks: harness::ui_layer2::sim_ui_every_value_moving_press_shows_its_dollars_and_warning_before_the_core_is_asked.
    assert!(!run.invoked.iter().any(|c| c == "wallet_cash_out"), "an unpriced sale asked the core: {:?}", run.invoked);
    assert!(!run.invoked.iter().any(|c| c == "wallet_unbond"), "Escape asked the core for nothing: {:?}", run.invoked);
}

/// ⭐ THE DRIVEN CENSUS FAILS ON A PLANTED DEFECT: the served `app.js` skips the dialog (`no_confirm`: the sell press asks
/// the core at once), or drops the `$` from every amount (`no_dollars`). Each must fail at the step that names it.
#[test]
fn the_driven_census_fails_when_the_dialog_is_skipped_or_its_dollars_dropped() {
    let census = "every value-moving invoke followed a click in a dialog showing dollars and a warning".to_string();
    let skipped = drive_with("value_moving_presses", None, Some("no_confirm"));
    assert!(!skipped.ok(), "a press with no dialog must fail: {}", skipped.report);
    let failed = skipped.failed_steps();
    assert!(failed.contains(&census) && failed.contains(&"the SAT send confirmation says plainly it has no dollar price and shows the fee in dollars".to_string()), "{failed:?}");
    let no_dollars = drive_with("value_moving_presses", None, Some("no_dollars"));
    assert!(!no_dollars.ok(), "a dialog with no dollars must fail: {}", no_dollars.report);
    let failed = no_dollars.failed_steps();
    assert!(failed.contains(&"the SAT send confirmation says plainly it has no dollar price and shows the fee in dollars".to_string()), "{failed:?}");
}

/// ⭐ ONE DECLARATION PER NAME: a shipped script loads as a classic script, where a second top-level `function f` silently
/// replaces the first for every caller. 1aa650f's rename turned `escPos → escHtml` into `escapeHtml → escapeHtml`, so the
/// later declaration won and every escaped render recursed until the stack overflowed. Seconds, no browser.
#[test]
fn every_top_level_function_in_a_shipped_script_is_declared_once() {
    let dist = wallet_root().join("dist");
    let mut files = vec![dist.join("app.js")];
    for sub in ["lib", "pages"] {
        for e in std::fs::read_dir(dist.join(sub)).expect("a shipped script dir").flatten() {
            if e.path().extension().and_then(|x| x.to_str()) == Some("js") {
                files.push(e.path());
            }
        }
    }
    let mut twice = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).expect("a shipped script");
        let mut seen = std::collections::BTreeMap::<String, usize>::new();
        for line in src.lines() {
            let decl = line.strip_prefix("async function ").or_else(|| line.strip_prefix("function "));
            let Some(rest) = decl else { continue };
            let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$').collect();
            if !name.is_empty() {
                *seen.entry(name).or_default() += 1;
            }
        }
        let file = f.file_name().expect("a file name").to_string_lossy().into_owned();
        twice.extend(seen.into_iter().filter(|(_, n)| *n > 1).map(|(name, n)| format!("{file}: {name} ×{n}")));
    }
    assert!(twice.is_empty(), "top-level functions declared more than once (the last silently wins): {twice:?}");
}

/// ⭐ R7 F3 — RESTORE FROM THE CHECKSUMMED MASTER KEY, driven through the shipped UI on the real core: Settings shows the
/// key, a one-character typo is refused by its checksum and opens nothing, and the true key reopens the wallet whose
/// address the CORE holds — the same one the create step showed. Calibration: a core that accepted any key would open a
/// wallet on the typo, and the step "the refused key opened no wallet" fails.
#[test]
fn the_shipped_restore_screen_refuses_a_mistyped_master_key_and_reopens_the_same_wallet_from_the_true_one() {
    let run = drive("restore_master_key", None);
    assert!(run.ok(), "⛔ the master-key restore flow failed at: {:?}", run.failed_steps());
    let shown = run.report["address_shown"].as_str().expect("the page reported the restored address").to_string();
    let held = crate::wallet_address().expect("the core holds an open wallet after the restore");
    let core = held["address"].as_str().expect("the core names its address").to_string();
    assert_eq!(shown, core, "⛔ the page showed an address the core does not hold");
    assert!(run.invoked.iter().any(|c| c == "wallet_restore"), "the restore reached the core through its own command");
}

/// ⭐ AUTO-OPSEC (user 2026-10-28) driven through the shipped UI on the real core: on by default; the toggle-off opens one
/// warning that the transactions will not be private; Cancel keeps it on; confirming turns it off IN THE CORE; turning it
/// back on asks nothing.
#[test]
fn auto_opsec_is_on_by_default_and_turns_off_only_through_its_not_private_warning() {
    let run = drive("auto_opsec_toggle", None);
    assert!(run.ok(), "⛔ the Auto-OPSEC flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_set_auto_opsec"), "the toggle reached the core");
}

/// ⭐ R7 F2 — restore from the 24 words through the shipped screens on the real core: the phrase shown at creation, typed
/// back after a lock, reopens the SAME wallet (the same address the core holds) in under a second; a phrase with one word
/// changed does not reopen it.
#[test]
fn the_shipped_restore_screen_reopens_the_same_wallet_from_its_24_words() {
    let run = drive("restore_phrase", None);
    assert!(run.ok(), "⛔ the restore-by-phrase flow failed at: {:?} — {}", run.failed_steps(), run.report);
}

/// ⭐ §22 4 (R7) — "BECOME A VALIDATOR" IN ONE TAP through the shipped UI on the real core: one tap opens ONE confirmation naming
/// the $0.00 fee, that the computer must stay online, the 21-day exit and what each slash costs; Cancel sends nothing; confirming
/// sends `wallet_become_validator` (value-moving: recorded at the door).
#[test]
fn become_a_validator_in_one_tap() {
    let run = drive("become_validator", None);
    assert!(run.ok(), "⛔ the Become-a-validator flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_become_validator"), "the one-tap bond reached the core");
}

/// ⭐ §22 4 — refused on a phone or tablet with the reason and the path that works there (delegate); every desktop OS may validate.
#[test]
fn becoming_a_validator_is_refused_on_a_phone_and_pointed_to_delegation() {
    for os in ["ios", "android"] {
        let why = crate::validator_platform_refusal(os).expect("refused on a phone");
        assert!(why.contains("stay online") && why.contains("Delegate"), "{os}: {why}");
    }
    for os in ["macos", "linux", "windows"] {
        assert_eq!(crate::validator_platform_refusal(os), None, "{os} may validate");
    }
}

/// ⭐ §BR-3 17.6 (R7 Earn) — a new wallet can stake USDm from the shipped Earn page: Claim and Unstake are disabled with
/// nothing staked, Stake with no amount is refused on screen, Stake opens ONE confirmation naming the dollars, unstake any
/// time and the fee pool, Cancel sends nothing, and confirming sends `wallet_stake` (value-moving: recorded at the door).
#[test]
fn the_earn_page_stakes_usdm_behind_one_dollar_confirmation() {
    let run = drive("stake_usdm", None);
    assert!(run.ok(), "{}", run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_stake"), "the stake reached the core");
}

/// ⭐ §BR-4 (R7 F8) — with no price on the chain (no node in this harness) the shipped Borrow page says borrowing is not
/// available yet, and Borrow opens no dialog and sends nothing. The priced flow — options, confirmation, deposit, the loan's
/// distance to liquidation, repayment — runs live in `harness::ui_layer2::sim_ui_borrow_*`.
#[test]
fn the_borrow_page_says_so_when_the_chain_cannot_price_bitcoin_and_opens_nothing() {
    let run = drive("borrow_no_price", None);
    assert!(run.ok(), "⛔ the Borrow page failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(!run.invoked.iter().any(|c| c == "wallet_borrow_open"), "⛔ a loan was asked for with nothing chosen");
}

/// ⭐ §BR-3 17.3 DELEGATE SAT (R7 F10) driven through the shipped UI on the real core: the card lists no delegation on a new
/// wallet; Delegate with no amount is refused on screen; Delegate opens ONE confirmation naming $0.00, the 21-day unbonding
/// and the slash risk, and Cancel sends nothing; confirming sends `wallet_delegate_sat`; Undelegate all opens its own
/// confirmation naming the 21 days and confirming sends `wallet_undelegate_sat` (value-moving: recorded at the door).
#[test]
fn delegating_sat_passes_one_confirmation_naming_the_cost_the_unbonding_and_the_slash_risk() {
    let run = drive("delegate_sat", None);
    assert!(run.ok(), "⛔ the Delegate SAT flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_delegate_sat"), "the delegation reached the core");
    assert!(run.invoked.iter().any(|c| c == "wallet_undelegate_sat"), "the undelegation reached the core");
}


/// ⭐ §BR-11 "BOND MY REWARDS" (R7 F15) driven through the shipped UI on the real core: off by default; turning it on opens
/// one confirmation naming $0.00 and the 21-day unbonding; Cancel keeps it off; confirming sends `wallet_set_bond_rewards` to
/// the core (a value-moving command: the harness records it at the door, after the dialog, and does not run it).
#[test]
fn bond_my_rewards_is_off_by_default_and_turns_on_only_through_its_cost_and_lock_confirmation() {
    let run = drive("bond_rewards_toggle", None);
    assert!(run.ok(), "⛔ the Bond my rewards flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_set_bond_rewards"), "the switch reached the core");
}

/// ⭐ §BR-8 (R6 row 8) "TAKE MY REWARDS IN BITCOIN" driven through the shipped UI on the real core: off by default; turning it
/// on opens one confirmation naming the per-piece fee in dollars and the privacy delay; Cancel keeps it off; confirming sends
/// `wallet_set_rewards_in_btc` (a value-moving command, recorded at the door after the dialog).
#[test]
fn take_my_rewards_in_bitcoin_is_off_by_default_and_turns_on_only_through_its_fee_and_delay_confirmation() {
    let run = drive("rewards_btc_toggle", None);
    assert!(run.ok(), "⛔ the rewards-in-Bitcoin flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_set_rewards_in_btc"), "the switch reached the core");
}

/// ⭐ §BR-8 B8-b (R6 row 8) THE REMIXER driven through the shipped UI on the real core: off by default; one confirmation naming
/// the per-round Bitcoin fee in dollars; Cancel keeps it off; confirming sends `wallet_set_remix` (value-moving, after the dialog).
#[test]
fn the_remixer_is_off_by_default_and_turns_on_only_through_its_fee_confirmation() {
    let run = drive("remix_toggle", None);
    assert!(run.ok(), "⛔ the remixer flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_set_remix"), "the switch reached the core");
}

/// ⭐ R7 F7 — A SWAP THROUGH THE WALLET shows the dollars paid and received and the 0.25 % wallet fee before confirming; Cancel
/// sends nothing (the app is told the user declined); confirming sends `dapp_provider_swap_execute` (value-moving, after the
/// dialog). Driven through the provider call IonSwap's page makes, on the shipped UI and the real core.
#[test]
fn a_swap_through_the_wallet_shows_its_dollars_and_the_wallet_fee_before_confirming() {
    let run = drive("swap_confirm", None);
    assert!(run.ok(), "⛔ the swap confirmation flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "dapp_provider_swap_execute"), "the confirmed swap reached the core");
}

/// ⭐ R7 F13 — A DSOL CALL THROUGH THE WALLET shows the PUBLISHER FEE in dollars before confirming (§BR-12): the deployed fee the
/// app hands over ($0.50; a second contract's $2.00 — the dollars follow the manifest), the network fee; Cancel sends nothing
/// (the app is told the user declined); confirming sends `dapp_provider_dsol_call` (value-moving, after the dialog). Driven
/// through the provider call a launchpad app makes, on the shipped UI and the real core. That the core verifies the manifest
/// against the chain's root BEFORE paying, and pays exactly the shown fee to the publisher, is `harness::ui_layer2`'s F13
/// journey and the node door's pins.
#[test]
fn a_dsol_call_through_the_wallet_shows_the_publisher_fee_in_dollars_before_confirming() {
    let run = drive("dsol_call_confirm", None);
    assert!(run.ok(), "⛔ the DSOL call confirmation flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "dapp_provider_dsol_call"), "the confirmed call reached the core");
}

/// The F13 dialog pin can fail: with the dollars planted out of the shipped `app.js` (`no_dollars`), the flow's dollar steps
/// go red — the pin is not vacuous.
#[test]
fn the_dsol_call_dialog_pin_fails_when_the_dollars_are_planted_out() {
    let run = drive_with("dsol_call_confirm", None, Some("no_dollars"));
    assert!(!run.ok(), "⛔ the F13 dialog pin passed with every dollar sign removed: {}", run.report);
}

/// ⭐ R7 F12 — the merchant sees the POS fee before charging: the 0.5 % note sits on the entry screen beside the card networks'
/// 2–3 %, on the shipped UI.
#[test]
fn the_merchant_sees_the_pos_fee_before_charging() {
    let run = drive("pos_fee_shown", None);
    assert!(run.ok(), "⛔ the POS fee flow failed at: {:?} — {}", run.failed_steps(), run.report);
}

/// ⭐ R7 F14 — the Updates card reads the core (no release three builders attest ⇒ up to date) and never offers an install.
#[test]
fn the_update_card_reads_the_core_and_offers_nothing_unattested() {
    let run = drive("update_card", None);
    assert!(run.ok(), "⛔ the Updates flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_update_status"), "the card asked the core");
}

/// ⭐ R7 F15 — the miner card shows the miner pool's payout in plain language beside "Bond my rewards" (off by default).
#[test]
fn the_miner_card_shows_the_pool_payout_beside_bond_my_rewards() {
    let run = drive("miner_pool_shown", None);
    assert!(run.ok(), "⛔ the miner card flow failed at: {:?} — {}", run.failed_steps(), run.report);
}

/// ⭐ §BR-15 R7 F16 — the BUY SAT screen on the shipped UI and the real core: "You get: SAT" offers USDm to pay with, the receive
/// line answers from the core's own book, the button reads "Buy SAT", and with no market open the press opens no dialog and
/// sends nothing value-moving. (The dollar confirmation itself is the static census's: `wallet_buy_sat` and
/// `wallet_buy_sat_deposit` are VALUE_MOVING, each call site awaiting `confirmCost` with dollars and a warning.)
#[test]
fn the_buy_sat_screen_offers_usdm_asks_the_core_and_moves_nothing_while_the_market_is_closed() {
    let run = drive("buy_sat_screen", None);
    assert!(run.ok(), "⛔ the Buy SAT screen flow failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_defi_book"), "the screen asked the core's book");
}

/// ⭐ ADOPTABLE A1 (user 2026-10-24: "getting USDm takes three taps or fewer") driven through the shipped UI on the real core:
/// from a fresh install, Create shows the 24 words (tap 1), "I've written it down" opens home (tap 2), "Add money with
/// Bitcoin" shows one private vault address (tap 3) — the core's own open deposit plan — with the costs in dollars beside it
/// before anything is sent. Counted click by click; a fourth tap fails it.
#[test]
fn getting_usdm_takes_three_taps_from_a_fresh_install() {
    let run = drive("add_money_three_taps", None);
    assert!(run.ok(), "⛔ A1 failed at: {:?} — {}", run.failed_steps(), run.report);
    assert!(run.report["taps"].as_u64().is_some_and(|t| t <= 3), "⛔ A1: more than three taps: {}", run.report);
    assert!(run.invoked.iter().any(|c| c == "wallet_mix_start"), "the address came from the core's deposit plan");
}
