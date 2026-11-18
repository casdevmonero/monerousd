// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// Two-machine MoneroPay BLE conformance probe — the device-to-device proof.
//
// This shares the SAME source the desktop wallet compiles (moneropay.rs = protocol, moneropay_ble.rs =
// Core Bluetooth radio) via `#[path]`, so a green run here proves the wallet's real tap path over TWO
// separate radios on TWO machines.
//
//   Mac A (merchant):  moneropay-ble-probe merchant "MoneroPay charge $5.00"
//   Mac B (payer):     moneropay-ble-probe payer
//
// The merchant advertises + seals the text under a fresh ML-KEM session; the payer scans, RSSI-range-gates,
// completes the handshake, and OPENS the sealed text over the air — printing it plus the measured distance.
// (macOS runs this unsigned; first Bluetooth use prompts "Terminal would like to use Bluetooth" → Allow.)

// The protocol core is cross-platform; the radio binding is Core Bluetooth (macOS/iOS).
#[path = "../../src-tauri/src/moneropay.rs"]
mod moneropay;
#[cfg(target_os = "macos")]
#[path = "../../src-tauri/src/moneropay_ble.rs"]
mod moneropay_ble;

#[cfg(target_os = "macos")]
fn main() {
    use std::time::Duration;
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()).unwrap_or("") {
        "merchant" => {
            let text = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "MoneroPay charge $5.00".to_string());
            println!("[merchant] advertising a sealed charge over BLE: {text:?}");
            println!("[merchant] (leave this running; start `moneropay-ble-probe payer` on the other Mac)");
            let handle = match moneropay_ble::start_merchant(text.into_bytes()) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[merchant] ❌ could not start advertising: {e}");
                    std::process::exit(1);
                }
            };
            // Keep advertising; surface live radio status. Ctrl-C to stop.
            loop {
                std::thread::sleep(Duration::from_secs(2));
                println!("[merchant] status: {}", handle.status_json());
            }
        }
        "payer" => {
            println!("[payer] scanning for a nearby MoneroPay merchant over the real Bluetooth radio…");
            match moneropay_ble::pay_nearby(Duration::from_secs(30)) {
                Ok(o) => {
                    println!(
                        "[payer] ✅ RECEIVED the sealed charge OVER THE AIR: {:?}",
                        String::from_utf8_lossy(&o.charge_bytes)
                    );
                    println!(
                        "[payer]    measured RSSI {} dBm · ~{:.0} cm · within tap range ✓",
                        o.rssi_dbm, o.distance_cm
                    );
                    println!("[payer]    (proves: two separate radios completed the ML-KEM handshake + opened the sealed charge)");
                }
                Err(e) => {
                    eprintln!("[payer] ❌ {e}");
                    std::process::exit(1);
                }
            }
        }
        "selftest" => {
            // One-machine real-radio loopback (advertise ⇄ tap on this Mac's single radio) — a quick
            // sanity check of the whole OTA loop before the two-Mac run.
            let charge = b"MoneroPay selftest charge".to_vec();
            match moneropay_ble::selftest_loopback(charge, Duration::from_secs(25)) {
                Ok(v) => println!("[selftest] {v}"),
                Err(e) => {
                    eprintln!("[selftest] ❌ {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: moneropay-ble-probe <merchant \"<text>\" | payer | selftest>");
            std::process::exit(2);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("moneropay-ble-probe: the Core Bluetooth radio binding is macOS/iOS; build on a Mac.");
    std::process::exit(2);
}
