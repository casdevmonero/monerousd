// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// MoneroPay BLE radio binding — the real Core Bluetooth transport for the MoneroPay tap protocol.
//
// The protocol brain (PQ session, sealed-charge AEAD, range gate, framing) lives in `moneropay.rs`
// and is tamper-tested; this module is the RADIO — a dumb byte pipe over Bluetooth Low Energy that
// carries those bytes between two MonerousD wallets. BLE was chosen over NFC because it needs NO paid
// Apple entitlement, NO paid developer account, and works iPhone↔iPhone↔Mac↔Android — the security
// is in the crypto, not the radio, so any free transport is exactly as secure. See moneropay.rs.
//
// TWO ROLES, ONE WALLET (universal by design):
//   • MERCHANT = BLE PERIPHERAL. `wallet_pos_charge` produces an ML-DSA-signed charge; the merchant
//     brings up a CBPeripheralManager, generates a fresh ML-KEM session keypair, advertises the
//     MoneroPay service, and serves a GATT with 4 characteristics (EK read / CT write / CHARGE notify
//     / ACK write). When a payer completes the ML-KEM handshake, the merchant SEALS the charge and
//     streams the frames over CHARGE — so the radio only ever sees ciphertext.
//   • PAYER   = BLE CENTRAL. The "Pay in person" tap brings up a CBCentralManager, scans for the
//     MoneroPay service, RANGE-GATES on RSSI (rejects an across-the-room / relayed merchant), reads EK,
//     encapsulates, writes CT, receives + reassembles + OPENS the sealed charge, and hands the plaintext
//     charge to the UNCHANGED wallet flow (verify_pos_charge → Face ID → wallet_pos_pay). BLE only
//     replaces "how the charge reaches the payer"; nothing about verify / biometric / spend changes.
//
// ZERO USER SETUP: no OS pairing/bonding, no manual Bluetooth config — the ML-KEM handshake IS the
// pairing, ephemeral per charge. The only OS prompt is the one-time Bluetooth permission.
//
// PROVABLE ON ONE MAC: two wallet instances on this machine (A advertises a charge, B taps to pay)
// talk over the REAL Bluetooth radio — a genuine two-endpoint proof with no phone. `selftest_loopback`
// does the same inside one process.
// Apple-native on BOTH macOS (desktop) and iOS (mobile) — Core Bluetooth is the identical framework on each, so
// the MoneroPay tap radio is at 100% parity across the desktop + iPhone builds of this one Tauri codebase.
#![cfg(any(target_os = "macos", target_os = "ios"))]
#![allow(non_snake_case)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use dispatch2::{DispatchQueue, DispatchRetained, DispatchTime};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DefinedClass, Message};
use objc2_foundation::{NSArray, NSData, NSDictionary, NSError, NSNumber, NSString};
use objc2_core_bluetooth::{
    CBAdvertisementDataServiceUUIDsKey, CBATTRequest, CBAttributePermissions, CBCentral,
    CBCentralManager, CBCentralManagerDelegate, CBCharacteristic, CBCharacteristicProperties,
    CBManager, CBManagerAuthorization, CBManagerState, CBMutableCharacteristic, CBMutableService,
    CBPeripheral, CBPeripheralDelegate, CBPeripheralManager, CBPeripheralManagerDelegate, CBService,
    CBUUID,
};

/// ⛔ PRE-FLIGHT THE TCC GRANT — MEASURED 2026-08-13: instantiating a CB manager WITHOUT Bluetooth
/// authorization ABORTS the whole process (SIGABRT/exit 134) with no catchable error — in the app that
/// is a CRASH in the middle of a payment tap. `CBManager::authorization()` is queryable WITHOUT touching
/// the radio, so every BLE entry point gates on it and returns a normal `Err` naming the exact grant the
/// user must make. Fail-closed and crash-free: no radio object is created unless allowed.
/// cons: one static objc call per BLE entry; `NotDetermined` (first-ever use in a GUI app context, where
/// the OS shows its own prompt on radio use) is allowed through so the system dialog can appear — only
/// an explicit Denied/Restricted refuses; cons otherwise: none.
fn bt_authorization_gate() -> Result<(), String> {
    let auth = unsafe { CBManager::authorization_class() };
    if auth == CBManagerAuthorization::Denied || auth == CBManagerAuthorization::Restricted {
        return Err(format!(
            "Bluetooth is not authorized for this process (state {:?}) — grant it in System Settings →              Privacy & Security → Bluetooth, then retry. Refusing to touch the radio: an unauthorized              CoreBluetooth instantiation aborts the whole process mid-payment.",
            auth.0
        ));
    }
    if auth == CBManagerAuthorization::NotDetermined {
        // MEASURED 2026-08-13 (bletap, exit 134 twice): NotDetermined + radio use from a BARE binary
        // aborts — the TCC prompt needs a GUI app context. Allow NotDetermined only inside a real .app
        // bundle (where the OS shows its prompt on first use); refuse it for terminal binaries with the
        // exact remediation. The path test is dependency-free and matches how macOS scopes the grant.
        let in_app_bundle = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.contains(".app/Contents/MacOS/")))
            .unwrap_or(false);
        // MUSD_BLE_FORCE=1: explicit USER-PRESENT override — the user is at the screen ready to click the
        // OS permission prompt, so let the attempt fire (macOS attributes the prompt to the hosting GUI
        // app). Default behaviour unchanged: bare binaries refuse, because unattended the attempt ABORTS.
        // cons: with FORCE set and no promptable host, the process still aborts (exit 134) — exactly the
        // pre-gate behaviour, now opt-in and user-witnessed instead of silent.
        let force = std::env::var("MUSD_BLE_FORCE").ok().as_deref() == Some("1");
        // iOS: every process IS a GUI app bundle (path shape `<name>.app/<exe>` — no Contents/MacOS,
        // so the macOS path probe above reads false) and the OS always attributes the CoreBluetooth
        // prompt to it. Without this, the phone's FIRST-ever tap is refused as a "bare binary" and the
        // permission prompt can never appear — a dead button on the primary tap platform.
        let in_app_bundle = in_app_bundle || cfg!(target_os = "ios");
        if !in_app_bundle && !force {
            return Err("Bluetooth authorization is NotDetermined and this is a bare (non-.app) binary - macOS cannot show the permission prompt here and CoreBluetooth would ABORT the process. Run the BLE flow once from the MoneroUSD Wallet.app (which can prompt), pre-grant this binary in System Settings > Privacy & Security > Bluetooth, or set MUSD_BLE_FORCE=1 while a user is present to click the OS prompt.".to_string());
        }
    }
    Ok(())
}

use crate::moneropay;
use usdmd_node::ble_frame::BleCellPump;
use usdmd_node::serve::ble_bridge;

// ── Small NSData helpers ────────────────────────────────────────────────────────────────────────
fn nsdata_from(bytes: &[u8]) -> Retained<NSData> {
    NSData::with_bytes(bytes)
}
fn nsdata_to_vec(d: &NSData) -> Vec<u8> {
    // `length` + `bytes` via raw message send (feature-independent across objc2-foundation builds).
    let len: usize = unsafe { msg_send![d, length] };
    if len == 0 {
        return Vec::new();
    }
    // SAFETY: `bytes` points to `len` valid bytes for the lifetime of `d`; we copy immediately.
    let ptr: *const core::ffi::c_void = unsafe { msg_send![d, bytes] };
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec()
}
fn cbuuid_from_16(raw: &[u8; 16]) -> Retained<CBUUID> {
    unsafe { CBUUID::UUIDWithData(&*nsdata_from(raw)) }
}

/// Deterministic single-use AEAD nonce for a fresh ML-KEM session: the charge is message #1, the paid
/// ack is #2. Safe because the session key is used exactly once (fresh ephemeral keypair per charge).
fn nonce_for(seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&seq.to_le_bytes());
    n
}

// Conservative BLE notify payload size (ATT MTU minus header) for framing; small charges fit in a few.
const MPAY_BLE_MTU: usize = 180;

// ── Node-cell pump cadence (the CORRECT liveness driver, not the easy one) ──
// The node's onion cells ride the SAME tap connection. Rather than pumping only when a Bluetooth event
// happens to fire (which stalls the instant both sides' queues momentarily empty), a self-rescheduling
// GCD timer runs ON the Core Bluetooth serial queue and flushes the node's outbound cells every tick —
// so convergence stays live even with zero inbound traffic, and every Core Bluetooth call still happens
// on the one queue that owns the delegate (no cross-thread radio access). `CELL_BURST` bounds how many
// whole cells we fragment per tick so one pass can never monopolize the queue.
const CELL_TICK_MS: u64 = 40;
const CELL_BURST: usize = 16;

/// The recurring on-queue cell timer's delay (NOW + `CELL_TICK_MS`). Falls back to NOW if the platform
/// can't build the delayed time (it would just tick immediately — never silently stops).
fn cell_tick_delay() -> DispatchTime {
    DispatchTime::try_from(Duration::from_millis(CELL_TICK_MS)).unwrap_or(DispatchTime::NOW)
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════
// MERCHANT  (BLE peripheral)
// ══════════════════════════════════════════════════════════════════════════════════════════════════

#[derive(Default)]
struct MerchantStatus {
    powered_on: bool,
    advertising: bool,
    session_established: bool, // a payer completed the ML-KEM handshake (CT received)
    charge_sent: bool,        // sealed charge frames streamed
    paid: bool,               // sealed paid-ack opened
    last_error: Option<String>,
}

struct MerchantShared {
    beacon_id: [u8; 16],           // fresh CSPRNG per charge — the ROTATING advertised service UUID (unlinkable)
    dk: moneropay::DecapsKey,       // this session's ML-KEM decapsulation key
    ek_bytes: Vec<u8>,              // the matching encaps key served over the EK characteristic
    charge_bytes: Vec<u8>,         // the ML-DSA-signed charge (serialized) to seal + serve
    session: Mutex<Option<[u8; 32]>>, // derived after CT arrives
    status: Mutex<MerchantStatus>,
    // characteristic handles created when the service is built (so notifies can target CHARGE)
    charge_chr: Mutex<Option<Retained<CBMutableCharacteristic>>>,
    // frames still to notify when the transmit queue frees up (peripheralManagerIsReadyToUpdateSubscribers)
    pending_frames: Mutex<Vec<Vec<u8>>>,
    /// EK frames still to notify. The key is 1184 bytes and one notification carries ~180.
    ek_pending: Mutex<Vec<Vec<u8>>>,
    /// Ciphertext frames received from the payer (1088 bytes, far past a single ATT write).
    ct_frames: Mutex<Vec<Vec<u8>>>,
    /// The live EK characteristic, retained so frames can be notified to it after subscribe.
    ek_chr: Mutex<Option<Retained<CBMutableCharacteristic>>>,
    // ── NODE CONVERGENCE over the same tap connection ──
    // `cell_pump` bridges this device's node (usdmd_node::serve::ble_bridge) to the CELL_DOWN/CELL_UP
    // characteristics; it is touched ONLY on the CB serial queue (timer + write callback), so its Mutex is
    // never contended. `cell_tx` holds fragments the transmit queue couldn't take yet (back-pressure — a
    // cell is never dropped mid-flight). `mgr`/`cell_down_chr` let the on-queue timer notify. `cell_subscribed`
    // gates draining until a central actually subscribes; `cell_run` stops the recurring timer at teardown.
    cell_pump: Mutex<BleCellPump>,
    cell_tx: Mutex<VecDeque<Vec<u8>>>,
    cell_down_chr: Mutex<Option<Retained<CBMutableCharacteristic>>>,
    mgr: Mutex<Option<Retained<CBPeripheralManager>>>,
    cell_subscribed: AtomicBool,
    cell_run: AtomicBool,
}
// The Retained CB handle is only ever touched on the CB queue; we gate all access through the Mutexes.
unsafe impl Send for MerchantShared {}
unsafe impl Sync for MerchantShared {}

struct MerchantIvars {
    shared: Arc<MerchantShared>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "MPayMerchantDelegate"]
    #[ivars = MerchantIvars]
    struct MerchantDelegate;

    unsafe impl NSObjectProtocol for MerchantDelegate {}

    unsafe impl CBPeripheralManagerDelegate for MerchantDelegate {
        // Radio powered on → build the GATT service (with the EK value baked in) and advertise it.
        #[unsafe(method(peripheralManagerDidUpdateState:))]
        fn did_update_state(&self, mgr: &CBPeripheralManager) {
            let sh = &self.ivars().shared;
            let state = unsafe { mgr.state() };
            let on = state == CBManagerState::PoweredOn;
            sh.status.lock().unwrap_or_else(|e| e.into_inner()).powered_on = on;
            if !on {
                sh.status.lock().unwrap_or_else(|e| e.into_inner()).last_error =
                    Some(format!("bluetooth not powered on (state {:?})", state));
                return;
            }
            // Serve under the ROTATING per-charge beacon id (a fresh random service UUID), NOT a static
            // MonerousD UUID — a passive BLE scanner sees only a random id that changes every charge
            // (metadata-privacy close: no "MonerousD tap here" fingerprint, no cross-charge linkage). A payer
            // identifies a genuine MoneroPay merchant only AFTER it connects, by the characteristic UUIDs below.
            let svc_uuid = cbuuid_from_16(&sh.beacon_id);
            // EK: NOTIFY, streamed in frames. It was a read-only characteristic with the 1184-byte key baked
            // in as a static value — but an ATT attribute cannot exceed 512 bytes, so every payer read came
            // back TRUNCATED and the ML-KEM session failed before a charge was ever sent. A static value must
            // also be `None` for a notifying characteristic, or Core Bluetooth rejects the service outright.
            let ek_chr: Retained<CBMutableCharacteristic> = unsafe {
                CBMutableCharacteristic::initWithType_properties_value_permissions(
                    CBMutableCharacteristic::alloc(),
                    &cbuuid_from_16(&moneropay::MONEROPAY_CHR_KEM_EK),
                    CBCharacteristicProperties::Notify,
                    None,
                    CBAttributePermissions::Readable,
                )
            };
            // CT: write (payer's ML-KEM ciphertext).
            let ct_chr: Retained<CBMutableCharacteristic> = unsafe {
                CBMutableCharacteristic::initWithType_properties_value_permissions(
                    CBMutableCharacteristic::alloc(),
                    &cbuuid_from_16(&moneropay::MONEROPAY_CHR_KEM_CT),
                    CBCharacteristicProperties::Write,
                    None,
                    CBAttributePermissions::Writeable,
                )
            };
            // CHARGE: notify (sealed charge frames).
            let charge_chr: Retained<CBMutableCharacteristic> = unsafe {
                CBMutableCharacteristic::initWithType_properties_value_permissions(
                    CBMutableCharacteristic::alloc(),
                    &cbuuid_from_16(&moneropay::MONEROPAY_CHR_CHARGE),
                    CBCharacteristicProperties::Notify,
                    None,
                    CBAttributePermissions::Readable,
                )
            };
            // ACK: write (sealed paid-ack from the payer).
            let ack_chr: Retained<CBMutableCharacteristic> = unsafe {
                CBMutableCharacteristic::initWithType_properties_value_permissions(
                    CBMutableCharacteristic::alloc(),
                    &cbuuid_from_16(&moneropay::MONEROPAY_CHR_ACK),
                    CBCharacteristicProperties::Write,
                    None,
                    CBAttributePermissions::Writeable,
                )
            };
            // CELL_DOWN: notify (node onion cells, merchant → payer) — the node-convergence leg of this tap.
            let cell_down_chr: Retained<CBMutableCharacteristic> = unsafe {
                CBMutableCharacteristic::initWithType_properties_value_permissions(
                    CBMutableCharacteristic::alloc(),
                    &cbuuid_from_16(&moneropay::MONEROPAY_CHR_CELL_DOWN),
                    CBCharacteristicProperties::Notify,
                    None,
                    CBAttributePermissions::Readable,
                )
            };
            // CELL_UP: write-with-response (node onion cells, payer → merchant). With-response so every
            // fragment arrives via didReceiveWriteRequests (the same proven, version-stable path as CT/ACK)
            // — reliability over raw throughput, which is the right call for convergence (cells re-gossip).
            let cell_up_chr: Retained<CBMutableCharacteristic> = unsafe {
                CBMutableCharacteristic::initWithType_properties_value_permissions(
                    CBMutableCharacteristic::alloc(),
                    &cbuuid_from_16(&moneropay::MONEROPAY_CHR_CELL_UP),
                    CBCharacteristicProperties::Write,
                    None,
                    CBAttributePermissions::Writeable,
                )
            };
            *sh.charge_chr.lock().unwrap_or_else(|e| e.into_inner()) = Some(charge_chr.clone());
            *sh.cell_down_chr.lock().unwrap_or_else(|e| e.into_inner()) = Some(cell_down_chr.clone());
            *sh.ek_chr.lock().unwrap_or_else(|e| e.into_inner()) = Some(ek_chr.clone());

            let service: Retained<CBMutableService> = unsafe {
                CBMutableService::initWithType_primary(CBMutableService::alloc(), &svc_uuid, true)
            };
            let chrs = NSArray::from_retained_slice(&[
                Retained::into_super(ek_chr),
                Retained::into_super(ct_chr),
                Retained::into_super(charge_chr),
                Retained::into_super(ack_chr),
                Retained::into_super(cell_down_chr),
                Retained::into_super(cell_up_chr),
            ]);
            unsafe { service.setCharacteristics(Some(&chrs)) };
            unsafe { mgr.addService(&service) };
        }

        // Service registered → start advertising the MoneroPay service UUID (identity-free: every
        // MoneroPay merchant advertises the SAME protocol UUID; nothing distinguishes one merchant).
        #[unsafe(method(peripheralManager:didAddService:error:))]
        fn did_add_service(
            &self,
            mgr: &CBPeripheralManager,
            _service: &CBService,
            error: Option<&NSError>,
        ) {
            let sh = &self.ivars().shared;
            if let Some(e) = error {
                sh.status.lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(format!("addService: {}", e));
                return;
            }
            // ⭐⭐⭐ ADVERTISE THE PROTOCOL MARKER *AND* THE PER-CHARGE PAYMENT ID.
            //
            // Only the rotating per-charge UUID was advertised, so a payer had nothing to filter on: it had to
            // CONNECT to every Bluetooth device nearby and probe its characteristics just to learn whether it
            // was a terminal at all. In a shop or a festival — many wallets, many unrelated devices — that is
            // both slow and wrong: it spends the tap window on headphones and laptops, and any device it
            // connects to learns a payer is looking. Measured here: 7 strangers probed in one window while the
            // real terminal was never reached.
            //
            // Two UUIDs fix it by construction:
            //   * `MONEROPAY_SERVICE_UUID16` — a FIXED protocol marker, so a scanner filters at the radio and
            //     never connects to a non-MoneroPay device. It identifies the PROTOCOL, not the user: every
            //     terminal in the world advertises the same one, so it carries no per-device information.
            //   * `beacon_id` — the per-charge PAYMENT ID, fresh CSPRNG per charge. This is what distinguishes
            //     THIS terminal's charge from the next stall's, and it is unlinkable across charges, so two
            //     charges from one merchant cannot be tied together.
            //
            // Privacy comes from the rotating id, never from hiding that MoneroPay exists — and correctness in
            // a crowd comes from the payer addressing a specific payment id rather than "whatever is closest".
            let marker = cbuuid_from_16(&moneropay::MONEROPAY_SERVICE_UUID16);
            let payment_id = cbuuid_from_16(&sh.beacon_id);
            let uuids = NSArray::from_retained_slice(&[
                Retained::into_super(marker),
                Retained::into_super(payment_id),
            ]);
            let obj: Retained<AnyObject> = Retained::into_super(Retained::into_super(uuids));
            let keys: &[&NSString] = unsafe { &[CBAdvertisementDataServiceUUIDsKey] };
            let vals: Vec<Retained<AnyObject>> = vec![obj];
            let adv = NSDictionary::from_retained_objects(keys, &vals);
            unsafe { mgr.startAdvertising(Some(&adv)) };
            sh.status.lock().unwrap_or_else(|e| e.into_inner()).advertising = true;
        }

        #[unsafe(method(peripheralManagerDidStartAdvertising:error:))]
        fn did_start_advertising(&self, _mgr: &CBPeripheralManager, error: Option<&NSError>) {
            let sh = &self.ivars().shared;
            if let Some(e) = error {
                sh.status.lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(format!("startAdvertising: {}", e));
                sh.status.lock().unwrap_or_else(|e| e.into_inner()).advertising = false;
            }
        }

        // A payer wrote to CT (ML-KEM handshake) or ACK (sealed paid-ack).
        #[unsafe(method(peripheralManager:didReceiveWriteRequests:))]
        fn did_receive_writes(&self, mgr: &CBPeripheralManager, requests: &NSArray<CBATTRequest>) {
            let sh = &self.ivars().shared;
            for i in 0..requests.count() {
                let req = requests.objectAtIndex(i);
                let chr = unsafe { req.characteristic() };
                let uuid_data = unsafe { chr.UUID().data() };
                let uuid = nsdata_to_vec(&uuid_data);
                let val = unsafe { req.value() }.map(|d| nsdata_to_vec(&d)).unwrap_or_default();

                if uuid == moneropay::MONEROPAY_CHR_KEM_CT {
                    merchant_trace(&format!("ct frame received: {} bytes", val.len()));
                    // The ciphertext arrives framed (see the payer's write). Collect until `reassemble`
                    // succeeds; ack each partial write so the payer keeps sending rather than stalling.
                    sh.ct_frames.lock().unwrap_or_else(|e| e.into_inner()).push(val.clone());
                    let ct_frames = sh.ct_frames.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let val = match moneropay::reassemble(&ct_frames) {
                        Ok(full) => {
                            merchant_trace(&format!("ciphertext COMPLETE: {} bytes from {} frame(s)", full.len(), ct_frames.len()));
                            full
                        }
                        Err(_) => {
                            unsafe { mgr.respondToRequest_withResult(&req, objc2_core_bluetooth::CBATTError::Success) };
                            continue; // more ciphertext frames still in flight
                        }
                    };
                    match moneropay::merchant_decaps(&sh.dk, &val) {
                        Ok(session) => {
                            // ⛔ `merchant_decaps` ALREADY returns the session key, exactly as `payer_encaps`
                            // does. BOTH BLE call sites re-derived it, so both held
                            // `session_key(session_key(ssk))` and — by accident — still agreed. Removing the
                            // re-derivation on ONE side only would have broken a working handshake, which is
                            // why both are corrected together. The single derivation now lives in one place
                            // (`moneropay.rs`), and `moneropay_session_roundtrip_seals_charge` is the
                            // definition both sides are held to.
                            *sh.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
                            sh.status.lock().unwrap_or_else(|e| e.into_inner()).session_established = true;
                            merchant_trace("decaps OK — session established");
                            // Seal the charge under the fresh session + stream it over CHARGE.
                            let sealed = moneropay::seal(&session, &nonce_for(1), &sh.charge_bytes);
                            let frames = moneropay::frame(&sealed, MPAY_BLE_MTU);
                            merchant_trace(&format!("charge sealed: {} bytes -> {} frame(s) queued", sealed.len(), frames.len()));
                            *sh.pending_frames.lock().unwrap_or_else(|e| e.into_inner()) = frames;
                            // ack the write first, then drain frames.
                            unsafe { mgr.respondToRequest_withResult(&req, objc2_core_bluetooth::CBATTError::Success) };
                            drain_merchant_frames(mgr, sh);
                            continue;
                        }
                        Err(e) => {
                            merchant_trace(&format!("decaps FAILED: {e}"));
                            sh.status.lock().unwrap_or_else(|e| e.into_inner()).last_error = Some(format!("decaps: {}", e));
                            unsafe { mgr.respondToRequest_withResult(&req, objc2_core_bluetooth::CBATTError::RequestNotSupported) };
                            continue;
                        }
                    }
                } else if uuid == moneropay::MONEROPAY_CHR_ACK {
                    if let Some(session) = *sh.session.lock().unwrap_or_else(|e| e.into_inner()) {
                        if let Ok(_ack) = moneropay::open(&session, &nonce_for(2), &val) {
                            sh.status.lock().unwrap_or_else(|e| e.into_inner()).paid = true;
                        }
                    }
                    unsafe { mgr.respondToRequest_withResult(&req, objc2_core_bluetooth::CBATTError::Success) };
                    continue;
                } else if uuid == moneropay::MONEROPAY_CHR_CELL_UP {
                    // A node-cell fragment from the payer's node → reassemble; a whole cell lands in our
                    // node's inbound bridge. Fail-open at the transport (a bad fragment just doesn't complete
                    // a cell, which re-gossips) — we always ACK the write so the payer keeps streaming.
                    let _ = sh.cell_pump.lock().unwrap_or_else(|e| e.into_inner()).on_fragment(&val);
                    unsafe { mgr.respondToRequest_withResult(&req, objc2_core_bluetooth::CBATTError::Success) };
                    continue;
                }
                unsafe { mgr.respondToRequest_withResult(&req, objc2_core_bluetooth::CBATTError::WriteNotPermitted) };
            }
        }

        // Transmit queue freed up → keep draining EVERY queue that can stall on it.
        //
        // ⛔ THE EK QUEUE BELONGS HERE. The encapsulation key is 1184 bytes = 7 notifications, and
        // `merchant_ek_flush` re-queues whatever the transmit queue would not take, to be resumed HERE. It was
        // missing, so a key that did not fit in one burst was never finished: the payer sat waiting for frames
        // that would never come, could not encapsulate, and therefore never wrote a ciphertext back.
        //
        // Measured on the phone, and this is the whole failure in one line — the merchant's own trace read
        // exactly `payer subscribed to EK — streaming the encapsulation key` and then nothing. No ciphertext
        // frame ever arrived, no decaps, no charge. A queue with no resume path is a stall with no error.
        #[unsafe(method(peripheralManagerIsReadyToUpdateSubscribers:))]
        fn ready_to_update(&self, mgr: &CBPeripheralManager) {
            merchant_ek_flush(mgr, &self.ivars().shared);
            drain_merchant_frames(mgr, &self.ivars().shared);
            merchant_cell_flush(&self.ivars().shared);
        }

        // A central subscribed to (or unsubscribed from) a notify characteristic. When it subscribes to
        // CELL_DOWN, the node-convergence leg is live → start draining cells to it; on unsubscribe, pause.
        #[unsafe(method(peripheralManager:central:didSubscribeToCharacteristic:))]
        fn did_subscribe(
            &self,
            mgr: &CBPeripheralManager,
            _central: &CBCentral,
            chr: &CBCharacteristic,
        ) {
            let sh = &self.ivars().shared;
            let ud = unsafe { chr.UUID().data() };
            let uuid = nsdata_to_vec(&ud);
            if uuid == moneropay::MONEROPAY_CHR_CELL_DOWN {
                sh.cell_subscribed.store(true, Ordering::SeqCst);
                merchant_cell_flush(sh);
            } else if uuid == moneropay::MONEROPAY_CHR_KEM_EK {
                merchant_trace("payer subscribed to EK — streaming the encapsulation key");
                // The payer is listening: stream the encapsulation key framed, the same path the sealed
                // charge takes. Nothing secret rides here — the EK is a PUBLIC ML-KEM key, and the session it
                // establishes is what makes the charge itself ciphertext on the air.
                // Frame OUTSIDE the lock, then install it — so a slow/failing framing step can never be
                // mistaken for a lock problem, and the count is on the record either way.
                let ek_frames = moneropay::frame(&sh.ek_bytes, MPAY_BLE_MTU);
                merchant_trace(&format!("EK framed: {} byte key -> {} frame(s)", sh.ek_bytes.len(), ek_frames.len()));
                *sh.ek_pending.lock().unwrap_or_else(|e| e.into_inner()) = ek_frames;
                merchant_ek_flush(mgr, sh);
            }
        }

        #[unsafe(method(peripheralManager:central:didUnsubscribeFromCharacteristic:))]
        fn did_unsubscribe(
            &self,
            _mgr: &CBPeripheralManager,
            _central: &CBCentral,
            chr: &CBCharacteristic,
        ) {
            let sh = &self.ivars().shared;
            let ud = unsafe { chr.UUID().data() };
            let uuid = nsdata_to_vec(&ud);
            if uuid == moneropay::MONEROPAY_CHR_CELL_DOWN {
                sh.cell_subscribed.store(false, Ordering::SeqCst);
            }
        }
    }
);

// ── Merchant node-cell pump (runs entirely on the CB serial queue) ──────────────────────────────────
/// One tick of the merchant's node-cell pump, on the CB queue: drain up to `CELL_BURST` of the node's
/// outbound cells into MTU fragments, then push as many as the transmit queue will take over CELL_DOWN.
fn merchant_cell_tick(sh: &Arc<MerchantShared>) {
    if !sh.cell_subscribed.load(Ordering::SeqCst) {
        return; // no central listening yet — leave cells in the node bridge (bounded, drop-oldest)
    }
    {
        let mut pump = sh.cell_pump.lock().unwrap_or_else(|e| e.into_inner());
        let mut tx = sh.cell_tx.lock().unwrap_or_else(|e| e.into_inner());
        // Drive at most what the queue can hold. `drive_outbound` takes only what it is asked for, so the
        // rest stays in the pump and goes out next tick — back-pressure, not loss.
        let burst = CELL_BURST.min(room_for(&tx));
        pump.drive_outbound(burst, |f| {
            let _ = push_bounded(&mut tx, f);
        });
    }
    merchant_cell_flush(sh);
}

/// Notify queued CELL_DOWN fragments until the transmit queue is full (updateValue → false), respecting
/// back-pressure exactly like the charge drain: a fragment that doesn't fit is put back and retried on the
/// next tick / peripheralManagerIsReadyToUpdateSubscribers. Never drops a fragment to congestion.
/// Drain the queued EK frames to the subscribed payer, mirroring [`merchant_cell_flush`].
///
/// The ML-KEM encapsulation key is 1184 bytes and one notification carries ~180, so it must be streamed. If
/// the transmit queue is full the remaining frames are put back and resume on
/// `peripheralManagerIsReadyToUpdateSubscribers` — dropping them instead would leave the payer holding a
/// partial key forever, which is indistinguishable from a merchant that never answered.
fn merchant_ek_flush(mgr: &CBPeripheralManager, sh: &Arc<MerchantShared>) {
    // ⛔ THE MANAGER COMES FROM THE CALLBACK, NOT FROM SHARED STATE. `sh.mgr` is never assigned anywhere in
    // this file, so reading it here returned `None` and this function returned BEFORE sending a single frame —
    // silently, on every call. The merchant's trace showed `streaming the encapsulation key` and then nothing
    // at all: not "complete", not "paused", because no frame was ever attempted. `drain_merchant_frames` takes
    // the manager as an argument for exactly this reason; the EK path simply did not.
    let chr = match sh.ek_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(c) => c,
        None => {
            // Rule 5: a silent return here is indistinguishable from "the key was sent". Say it.
            merchant_trace("EK flush ABORTED — no EK characteristic handle was ever stored");
            return;
        }
    };
    loop {
        // ⛔ NEVER HOLD THIS LOCK ACROSS FILE I/O. `merchant_trace` writes to disk; doing that while holding
        // `ek_pending` means any other holder of the same lock on this serial delegate queue waits on a disk
        // write, and the whole BLE delegate stalls with no error. Decide under the lock, report after it.
        let (frag, drained) = {
            let mut q = sh.ek_pending.lock().unwrap_or_else(|e| e.into_inner());
            if q.is_empty() {
                (None, false)
            } else {
                let f = q.remove(0);
                (Some(f), q.is_empty())
            }
        };
        let frag = match frag {
            Some(f) => f,
            None => {
                merchant_trace("EK flush found an EMPTY queue — nothing was queued to send");
                return;
            }
        };
        if drained {
            merchant_trace("EK stream COMPLETE — full encapsulation key delivered");
        }
        let ok = unsafe {
            mgr.updateValue_forCharacteristic_onSubscribedCentrals(&*nsdata_from(&frag), &chr, None)
        };
        if !ok {
            let left = {
                let mut q = sh.ek_pending.lock().unwrap_or_else(|e| e.into_inner());
                q.insert(0, frag);
                q.len()
            }; // lock released BEFORE the trace below writes to disk
            merchant_trace(&format!("EK stream paused with {left} frame(s) left — resuming when the queue frees"));
            return;
        }
    }
}


/// ⭐ THE MERCHANT'S OWN ACCOUNT OF A TAP, WRITTEN WHERE IT CAN BE READ OFF THE DEVICE.
///
/// On a phone the merchant is a black box: `eprintln!` goes to a stderr nobody collects — `devicectl
/// --console` captured ZERO lines — so a tap that failed on the merchant side reported nothing anywhere. Every
/// fix then had to be guessed from the payer's side alone, which is how three separate ATT/pacing bugs each
/// took a full build-install-tap cycle to find.
///
/// Appends one line per step into the app's own Documents container, retrievable with
/// `xcrun devicectl device copy from`. On desktop it lands beside the wallet data and costs nothing.
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: step names and byte LENGTHS only — never a key, commitment, amount, address
/// or nullifier. It records what the protocol did, not what was paid. The file stays inside the app's own
/// sandbox and is never transmitted.
/// ⛔⛔⛔ A POISONED MUTEX MUST NEVER KILL THE RADIO.
///
/// Every lock in this file used `.lock().unwrap()`, which PANICS if any thread previously panicked while
/// holding that mutex. On a serial CoreBluetooth delegate queue that is fatal and invisible: the first panic
/// poisons the lock, every later handler panics on entry, and the queue simply stops — no error, no timeout of
/// its own, just a peer that appears to have gone quiet mid-handshake. That is the exact signature chased for
/// hours today, most recently `charge sealed … queued` followed by silence, with `drain_merchant_frames` never
/// reaching even its first trace.
///
/// `unwrap_or_else(|e| e.into_inner())` takes the data anyway — the convention already used in 73 places in
/// `lib.rs`. A poisoned lock means someone panicked earlier, not that this data is unusable, and losing the
/// radio is far worse than proceeding with state a previous panic touched.

fn merchant_trace(step: &str) {
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let path = std::path::Path::new(&base).join("Documents").join("moneropay-merchant.log");
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "{step}");
    }
    eprintln!("[merchant] {step}");
}

fn merchant_cell_flush(sh: &Arc<MerchantShared>) {
    let mgr = match sh.mgr.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(m) => m,
        None => return,
    };
    let chr = match sh.cell_down_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(c) => c,
        None => return,
    };
    loop {
        let next = sh.cell_tx.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
        let frag = match next {
            Some(f) => f,
            None => return,
        };
        let ok = unsafe {
            mgr.updateValue_forCharacteristic_onSubscribedCentrals(&*nsdata_from(&frag), &chr, None)
        };
        if !ok {
            sh.cell_tx.lock().unwrap_or_else(|e| e.into_inner()).push_front(frag); // queue full — resume later
            return;
        }
    }
}

/// Schedule the merchant's recurring cell tick on the CB serial `queue`. Re-arms itself every
/// `CELL_TICK_MS` until `cell_run` clears — GUARANTEED liveness with zero dependence on inbound events,
/// and every Core Bluetooth call stays on the one queue that owns the delegate.
fn arm_merchant_cell_timer(queue: DispatchRetained<DispatchQueue>, sh: Arc<MerchantShared>) {
    if !sh.cell_run.load(Ordering::SeqCst) {
        return;
    }
    let q_next = queue.clone();
    let _ = queue.after(cell_tick_delay(), move || {
        merchant_cell_tick(&sh);
        arm_merchant_cell_timer(q_next, sh);
    });
}

/// Bounded fragment buffer push (drop-oldest) — a lossy/slow link can never grow wallet RAM; a dropped
/// fragment simply loses one in-flight cell, which the constant-rate cell re-gossip re-sends (no-growth).
/// The transmit queue's cap. Bounding it is right — an unbounded queue is its own failure — but the response
/// to a full queue must be BACK-PRESSURE, never a silent eviction.
pub(crate) const CELL_TX_CAP: usize = 512;

/// Queue one frame. NEVER discards.
///
/// ⛔ THIS USED TO `pop_front()` WHEN FULL. A sealed charge is split across frames, so losing one does not
/// degrade the tap — it makes the charge unreassemblable, and the payer sees a tap that does nothing at all.
/// The drop was invisible: nothing returned an error, nothing logged, and the queue looked healthy. Measured
/// by test: pushing 600 frames left 512, with frames #0..#87 gone.
///
/// Callers must not offer more than [`room_for`] allows; this returns `false` if they do, so a mistake is
/// visible instead of silently eating someone's payment. ([[feedback_no_windows_no_caps_cardinal]])
fn push_bounded(q: &mut VecDeque<Vec<u8>>, f: Vec<u8>) -> bool {
    if q.len() >= CELL_TX_CAP {
        return false; // refuse — the caller retries next tick; a payment frame is never thrown away
    }
    q.push_back(f);
    true
}

/// How many more frames the transmit queue can accept right now. Drive no more cells than this.
fn room_for(q: &VecDeque<Vec<u8>>) -> usize {
    CELL_TX_CAP.saturating_sub(q.len())
}

// Stream the pending sealed-charge frames over the CHARGE characteristic, respecting back-pressure
// (updateValue returns false when the queue is full → we stop and resume on ready_to_update).
fn drain_merchant_frames(mgr: &CBPeripheralManager, sh: &Arc<MerchantShared>) {
    let charge_chr = match sh.charge_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(c) => c,
        None => {
            // Rule 5: the last silent exit on the charge path. The merchant sealed a charge and queued it;
            // if this returns quietly the payer waits forever for something that was never sent.
            merchant_trace("charge drain ABORTED — no charge characteristic handle");
            return;
        }
    };
    loop {
        let next = {
            let mut q = sh.pending_frames.lock().unwrap_or_else(|e| e.into_inner());
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        };
        match next {
            None => {
                sh.status.lock().unwrap_or_else(|e| e.into_inner()).charge_sent = true;
                merchant_trace("charge stream COMPLETE — every sealed frame handed to the radio");
                return;
            }
            Some(frame) => {
                let ok = unsafe {
                    mgr.updateValue_forCharacteristic_onSubscribedCentrals(
                        &*nsdata_from(&frame),
                        &charge_chr,
                        None,
                    )
                };
                if !ok {
                    // queue full — put it back; ready_to_update will resume the drain.
                    let left = { let mut q = sh.pending_frames.lock().unwrap_or_else(|e| e.into_inner()); q.insert(0, frame); q.len() };
                    merchant_trace(&format!("charge stream paused with {left} frame(s) left — resuming when the queue frees"));
                    return;
                }
            }
        }
    }
}

/// Live handle to a running merchant advertiser. Dropping it (or `stop`) tears down the radio.
pub struct MerchantHandle {
    stop_tx: Sender<()>,
    shared: Arc<MerchantShared>,
}
impl MerchantHandle {
    pub fn status_json(&self) -> serde_json::Value {
        let s = self.shared.status.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::json!({
            "powered_on": s.powered_on,
            "advertising": s.advertising,
            "session_established": s.session_established,
            "charge_sent": s.charge_sent,
            "paid": s.paid,
            "last_error": s.last_error,
        })
    }
    pub fn stop(&self) {
        self.shared.cell_run.store(false, Ordering::SeqCst); // stop the recurring cell timer promptly
        let _ = self.stop_tx.send(());
    }
}

/// Bring up a MoneroPay merchant that advertises + serves the given (ML-DSA-signed) charge bytes over
/// real BLE until stopped. The CB manager + delegate live on the spawned thread; callbacks run on a
/// dedicated serial GCD queue. Returns immediately with a live status handle.
pub fn start_merchant(charge_bytes: Vec<u8>) -> Result<MerchantHandle, String> {
    bt_authorization_gate()?;
    let (ek_bytes, dk) = moneropay::merchant_new_kem().map_err(|e| e.to_string())?;
    let shared = Arc::new(MerchantShared {
        ek_pending: Mutex::new(Vec::new()),
        ct_frames: Mutex::new(Vec::new()),
        ek_chr: Mutex::new(None),
        beacon_id: moneropay::fresh_beacon_id(),
        dk,
        ek_bytes,
        charge_bytes,
        session: Mutex::new(None),
        status: Mutex::new(MerchantStatus::default()),
        charge_chr: Mutex::new(None),
        pending_frames: Mutex::new(Vec::new()),
        // The node-cell pump bridges THIS device's in-process node to the tap connection.
        cell_pump: Mutex::new(BleCellPump::new(ble_bridge(), MPAY_BLE_MTU)),
        cell_tx: Mutex::new(VecDeque::new()),
        cell_down_chr: Mutex::new(None),
        mgr: Mutex::new(None),
        cell_subscribed: AtomicBool::new(false),
        cell_run: AtomicBool::new(true),
    });
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let shared_thread = shared.clone();
    std::thread::spawn(move || {
        let queue = dispatch2::DispatchQueue::new("org.monerousd.moneropay.merchant", None);
        let ivars = MerchantIvars { shared: shared_thread.clone() };
        let this = MerchantDelegate::alloc().set_ivars(ivars);
        let delegate: Retained<MerchantDelegate> = unsafe { msg_send![super(this), init] };
        let proto = ProtocolObject::from_ref(&*delegate);
        let mgr: Retained<CBPeripheralManager> = unsafe {
            CBPeripheralManager::initWithDelegate_queue(
                CBPeripheralManager::alloc(),
                Some(proto),
                Some(&queue),
            )
        };
        // Publish the manager so the on-queue cell timer can notify CELL_DOWN, then start the recurring
        // node-cell pump on this same serial queue (guaranteed-live convergence, no cross-thread radio).
        *shared_thread.mgr.lock().unwrap_or_else(|e| e.into_inner()) = Some(mgr.clone());
        arm_merchant_cell_timer(queue.clone(), shared_thread.clone());
        // Park until stopped; the CB manager + delegate stay alive (radio serves on the GCD queue).
        let _ = stop_rx.recv();
        shared_thread.cell_run.store(false, Ordering::SeqCst);
        unsafe { mgr.stopAdvertising() };
        drop(mgr);
        drop(delegate);
    });
    Ok(MerchantHandle { stop_tx, shared })
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════
// PAYER  (BLE central)
// ══════════════════════════════════════════════════════════════════════════════════════════════════

struct PayerShared {
    // filled as the handshake progresses
    session: Mutex<Option<[u8; 32]>>,
    frames: Mutex<Vec<Vec<u8>>>,
    /// EK frames. The ML-KEM encapsulation key is 1184 bytes — far past the 512-byte ATT attribute ceiling —
    /// so it streams framed exactly like the charge, and is reassembled before `payer_encaps` ever sees it.
    ek_frames: Mutex<Vec<Vec<u8>>>,
    /// ML-KEM ciphertext frames still to write, and whether one is outstanding. CoreBluetooth accepts exactly
    /// ONE write-with-response at a time; the rest of a burst is dropped.
    ct_tx: Mutex<std::collections::VecDeque<Vec<u8>>>,
    ct_write_inflight: std::sync::atomic::AtomicBool,
    rssi_dbm: Mutex<i16>,
    discovered_rssi: Mutex<Option<i16>>, // real measured RSSI of the first MoneroPay merchant seen (pre-gate, diagnostic)
    peripheral: Mutex<Option<Retained<CBPeripheral>>>,
    /// The central manager, so a peripheral that turns out not to be a MoneroPay terminal can be released
    /// and scanning resumed. Without it, `stopScan()` at discovery is terminal: one wrong device ends the tap.
    central: Mutex<Option<Retained<CBCentralManager>>>,
    /// Peripherals already probed and found NOT to be MoneroPay terminals. Without this the scan re-discovers
    /// the same nearby device, connects, probes, releases, and repeats — burning the whole tap window on one
    /// stranger while the real terminal is never reached. Measured: 7 releases in a single window.
    not_terminals: Mutex<std::collections::HashSet<String>>,
    ct_chr: Mutex<Option<Retained<CBCharacteristic>>>,
    done_tx: Mutex<Option<Sender<Result<PayerOutcome, String>>>>,
    // ── NODE CONVERGENCE over the same tap connection (central side) ──
    // Mirrors the merchant: `cell_pump` bridges THIS device's node to the CELL_UP/CELL_DOWN characteristics
    // (touched only on the CB serial queue). Outbound cells are written UP one-at-a-time, paced by the
    // didWriteValue completion (`cell_write_inflight`) so CoreBluetooth's write queue never floods.
    // `cell_ready` gates draining until CELL_DOWN is subscribed + CELL_UP discovered; `cell_run` stops the timer.
    cell_pump: Mutex<BleCellPump>,
    cell_tx: Mutex<VecDeque<Vec<u8>>>,
    cell_up_chr: Mutex<Option<Retained<CBCharacteristic>>>,
    cell_ready: AtomicBool,
    cell_write_inflight: AtomicBool,
    cell_run: AtomicBool,
}
unsafe impl Send for PayerShared {}
unsafe impl Sync for PayerShared {}

#[derive(Clone)]
pub struct PayerOutcome {
    pub charge_bytes: Vec<u8>,
    pub rssi_dbm: i16,
    pub distance_cm: f64,
}

struct PayerIvars {
    shared: Arc<PayerShared>,
}

fn payer_finish(sh: &Arc<PayerShared>, result: Result<PayerOutcome, String>) {
    if let Some(tx) = sh.done_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = tx.send(result);
    }
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "MPayPayerDelegate"]
    #[ivars = PayerIvars]
    struct PayerDelegate;

    unsafe impl NSObjectProtocol for PayerDelegate {}

    unsafe impl CBCentralManagerDelegate for PayerDelegate {
        // Radio powered on → scan for MoneroPay merchants (by service UUID).
        #[unsafe(method(centralManagerDidUpdateState:))]
        fn central_did_update_state(&self, mgr: &CBCentralManager) {
            let state = unsafe { mgr.state() };
            if state != CBManagerState::PoweredOn {
                return;
            }
            // Scan UNFILTERED (services: None). macOS can drop a 128-bit *custom* service UUID from a
            // FILTERED local scan (it can ride the scan-response / overflow area), so a `[uuid]` filter
            // is not reliable across every Mac/iOS build. An unfiltered scan delivers every advert and we
            // re-check the MoneroPay service UUID in didDiscover below — strictly more robust for real
            // two-device taps, with zero loss of identity-correctness (still only MoneroPay merchants).
            // Filter at the radio on the MoneroPay protocol marker: a device that does not advertise it is
            // never connected to, so a crowded room costs nothing and no stranger learns we are paying.
            let want: Retained<NSArray<CBUUID>> =
                NSArray::from_retained_slice(&[cbuuid_from_16(&moneropay::MONEROPAY_SERVICE_UUID16)]);
            unsafe { mgr.scanForPeripheralsWithServices_options(Some(&want), None) };
        }

        // Discovered a merchant → RANGE-GATE on RSSI (reject an across-the-room / relayed merchant),
        // then connect to the nearest in-range one.
        #[unsafe(method(centralManager:didDiscoverPeripheral:advertisementData:RSSI:))]
        fn did_discover(
            &self,
            mgr: &CBCentralManager,
            peripheral: &CBPeripheral,
            _adv: &NSDictionary<NSString, AnyObject>, // advertised UUID is random per charge — not used to filter
            rssi: &NSNumber,
        ) {
            let sh = &self.ivars().shared;
            // METADATA PRIVACY: the merchant advertises a ROTATING RANDOM service UUID (no static MonerousD
            // fingerprint), so we CANNOT — and must not need to — identify a MoneroPay merchant from the
            // advertisement. Instead we RANGE-GATE to a deliberate TAP distance and connect to the closest
            // in-range peripheral, then confirm it is genuinely MoneroPay AFTER connecting, by its characteristic
            // UUIDs (`did_discover_chars`); a non-MoneroPay device is dropped and scanning resumes. A tap = the
            // phone held right to the terminal, so the closest strong-RSSI device in tap range IS the terminal.
            let rssi_dbm = rssi.as_i16();
            // ⛔ REPORT THE STRONGEST CANDIDATE, NOT THE FIRST STRANGER SEEN.
            //
            // This latched the FIRST peripheral the scan returned and never updated — and MoneroPay identity
            // is only confirmed AFTER connecting (see the comment above), so that first device was usually not
            // a terminal at all. The failure message then quoted an unrelated laptop's or headphones' signal
            // as "a MoneroPay merchant was seen at RSSI -96 dBm — hold the wallets closer", while the phone sat
            // next to the Mac. A stationary phone appeared to swing from -37 to -97 between runs because each
            // run reported a DIFFERENT device.
            //
            // Keeping the strongest reading makes the diagnostic describe the nearest thing that could plausibly
            // be the terminal, so "too far" only ever means nothing near was found.
            if rssi_dbm < 0 {
                let mut best = sh.discovered_rssi.lock().unwrap_or_else(|e| e.into_inner());
                if best.map(|b| rssi_dbm > b).unwrap_or(true) {
                    *best = Some(rssi_dbm);
                }
            }
            // Ignore obviously-invalid RSSI (0 / 127 are "unavailable" sentinels).
            if rssi_dbm >= 0 {
                return;
            }
            if !moneropay::within_tap_range(rssi_dbm, moneropay::MONEROPAY_RSSI_AT_1M_DBM) {
                return; // too far / relayed — keep scanning for a genuine tap
            }
            // Already proven not to be a terminal — do not spend this tap window on it again.
            let pid = unsafe { peripheral.identifier() }.UUIDString().to_string();
            if sh.not_terminals.lock().unwrap_or_else(|e| e.into_inner()).contains(&pid) {
                return;
            }
            // In tap range: lock onto the closest peer and probe it for MoneroPay after connecting.
            if sh.peripheral.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                return; // already connecting/probing one
            }
            *sh.rssi_dbm.lock().unwrap_or_else(|e| e.into_inner()) = rssi_dbm;
            *sh.peripheral.lock().unwrap_or_else(|e| e.into_inner()) = Some(peripheral.retain());
            unsafe { mgr.stopScan() };
            unsafe { mgr.connectPeripheral_options(peripheral, None) };
        }

        #[unsafe(method(centralManager:didConnectPeripheral:))]
        fn did_connect(&self, _mgr: &CBCentralManager, peripheral: &CBPeripheral) {
            let sh = &self.ivars().shared;
            let proto = ProtocolObject::from_ref(self);
            unsafe { peripheral.setDelegate(Some(proto)) };
            // The merchant's service UUID is a RANDOM per-charge id, so discover ALL services and identify the
            // MoneroPay one by its characteristic UUIDs in `did_discover_chars` (visible only post-connect).
            unsafe { peripheral.discoverServices(None) };
            let _ = sh; // keep sh referenced
        }

        #[unsafe(method(centralManager:didFailToConnectPeripheral:error:))]
        fn did_fail_connect(
            &self,
            _mgr: &CBCentralManager,
            _peripheral: &CBPeripheral,
            error: Option<&NSError>,
        ) {
            let msg = error.map(|e| e.to_string()).unwrap_or_else(|| "connect failed".into());
            payer_finish(&self.ivars().shared, Err(msg));
        }
    }

    unsafe impl CBPeripheralDelegate for PayerDelegate {
        #[unsafe(method(peripheral:didDiscoverServices:))]
        fn did_discover_services(&self, peripheral: &CBPeripheral, error: Option<&NSError>) {
            if let Some(e) = error {
                payer_finish(&self.ivars().shared, Err(format!("discoverServices: {}", e)));
                return;
            }
            let svcs = match unsafe { peripheral.services() } {
                Some(s) => s,
                None => return,
            };
            let want = [
                cbuuid_from_16(&moneropay::MONEROPAY_CHR_KEM_EK),
                cbuuid_from_16(&moneropay::MONEROPAY_CHR_KEM_CT),
                cbuuid_from_16(&moneropay::MONEROPAY_CHR_CHARGE),
                cbuuid_from_16(&moneropay::MONEROPAY_CHR_ACK),
                cbuuid_from_16(&moneropay::MONEROPAY_CHR_CELL_DOWN),
                cbuuid_from_16(&moneropay::MONEROPAY_CHR_CELL_UP),
            ];
            let want_arr = NSArray::from_retained_slice(&want);
            for i in 0..svcs.count() {
                let svc = svcs.objectAtIndex(i);
                unsafe { peripheral.discoverCharacteristics_forService(Some(&want_arr), &svc) };
            }
        }

        #[unsafe(method(peripheral:didDiscoverCharacteristicsForService:error:))]
        fn did_discover_chars(
            &self,
            peripheral: &CBPeripheral,
            service: &CBService,
            error: Option<&NSError>,
        ) {
            let sh = &self.ivars().shared;
            if let Some(e) = error {
                payer_finish(sh, Err(format!("discoverCharacteristics: {}", e)));
                return;
            }
            // ⛔ THIS CALLBACK FIRES PER SERVICE, NOT PER DEVICE — NEVER DROP A PEER FROM ONE SERVICE.
            //
            // A release was done here when a service carried no MoneroPay characteristic. But iOS reports
            // SEVERAL services per peripheral, and only one of the terminal's is MoneroPay — so the first
            // unrelated service caused the REAL terminal to be dropped mid-connect. Measured at `RSSI -20 dBm
            // (~1 cm)`: the payer released the very device it had just correctly found, and the merchant's log
            // stayed empty because no subscribe ever followed.
            //
            // Eliminating strangers belongs at the radio, where it now happens: the scan filters on the fixed
            // `MONEROPAY_SERVICE_UUID16` marker, so a non-MoneroPay device is never connected to at all. A
            // service without our characteristics is simply not the one we want — skip it and read the next.
            let chrs = match unsafe { service.characteristics() } {
                Some(c) => c,
                None => return,
            };
            for i in 0..chrs.count() {
                let chr = chrs.objectAtIndex(i);
                let uuid_data = unsafe { chr.UUID().data() };
                let uuid = nsdata_to_vec(&uuid_data);
                if uuid == moneropay::MONEROPAY_CHR_CHARGE {
                    unsafe { peripheral.setNotifyValue_forCharacteristic(true, &chr) };
                } else if uuid == moneropay::MONEROPAY_CHR_KEM_EK {
                    // ⛔ A SINGLE READ CANNOT CARRY AN ML-KEM KEY. This called `readValueForCharacteristic`,
                    // but an ATT attribute tops out at 512 bytes and the encapsulation key is 1184 — so the
                    // payer received a TRUNCATED key and `payer_encaps` failed its `[u8; 1184]` conversion
                    // every single time. Measured on a real iPhone-to-Mac tap: the devices connected, the
                    // session was attempted, and it died with "ML-KEM session failure" at every attempt.
                    // Subscribe and take it framed, the way the charge already travels.
                    unsafe { peripheral.setNotifyValue_forCharacteristic(true, &chr) };
                } else if uuid == moneropay::MONEROPAY_CHR_KEM_CT {
                    *sh.ct_chr.lock().unwrap_or_else(|e| e.into_inner()) = Some(chr.clone());
                } else if uuid == moneropay::MONEROPAY_CHR_CELL_DOWN {
                    // Subscribe to the node-cell DOWN stream; cell_ready flips on when the subscription confirms.
                    unsafe { peripheral.setNotifyValue_forCharacteristic(true, &chr) };
                } else if uuid == moneropay::MONEROPAY_CHR_CELL_UP {
                    *sh.cell_up_chr.lock().unwrap_or_else(|e| e.into_inner()) = Some(chr.clone()); // where we WRITE node cells up
                }
            }
        }

        // EK read result → ML-KEM encaps → write CT. CHARGE notify frames → reassemble → open charge.
        #[unsafe(method(peripheral:didUpdateValueForCharacteristic:error:))]
        fn did_update_value(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            let sh = &self.ivars().shared;
            if let Some(e) = error {
                payer_finish(sh, Err(format!("updateValue: {}", e)));
                return;
            }
            let uuid_data = unsafe { characteristic.UUID().data() };
            let uuid = nsdata_to_vec(&uuid_data);
            let val = unsafe { characteristic.value() }.map(|d| nsdata_to_vec(&d)).unwrap_or_default();

            if uuid == moneropay::MONEROPAY_CHR_KEM_EK {
                // Accumulate until the whole key is present. `reassemble` returns Err while frames are still
                // missing, so this simply waits rather than failing the tap on a partial key.
                let n = {
                    let mut q = sh.ek_frames.lock().unwrap_or_else(|e| e.into_inner());
                    q.push(val);
                    q.len()
                };
                let ek_frames = sh.ek_frames.lock().unwrap_or_else(|e| e.into_inner()).clone();
                // Distinguish "no frames arrived" from "frames arrived but never completed". Without this the
                // two are indistinguishable: the encaps trace below only fires on a COMPLETE key, so a single
                // dropped frame looks exactly like a payer that received nothing at all.
                let val = match moneropay::reassemble(&ek_frames) {
                    Ok(full) => {
                        eprintln!("[payer] EK frame {n} received — key COMPLETE ({} bytes)", full.len());
                        full
                    }
                    Err(_) => {
                        eprintln!("[payer] EK frame {n} received — key still incomplete, waiting for more");
                        return;
                    }
                };
                match moneropay::payer_encaps(&val) {
                    Ok((ct, payer_session)) => {
                        // ⛔ DO NOT DERIVE AGAIN. `payer_encaps` ALREADY returns the MoneroPay session key
                        // (`session_key(ssk)`), exactly as `merchant_decaps` does — the two are symmetric, and
                        // `moneropay_session_roundtrip_seals_charge` asserts they match. Applying `session_key`
                        // to that result a second time gave the payer `session_key(session_key(ssk))` while the
                        // merchant held `session_key(ssk)`, so the sealed charge could never be opened no matter
                        // how well the radio worked. The unit test stayed green throughout because it never runs
                        // this BLE path — a function proven correct, then mis-wired one call later.
                        *sh.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(payer_session);
                        // ⛔ BIND THE CLONE FIRST SO THE GUARD DROPS. Written as
                        // `if let Some(x) = sh.ct_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {`, Rust keeps the temporary
                        // MutexGuard alive for the ENTIRE body — so anything inside that touches `ct_chr`
                        // again (here: `payer_ct_flush`, which reads it first thing) deadlocks the BLE
                        // delegate queue on its own thread. Measured twice: the payer logged `encaps OK …
                        // 7 frame(s) queued` and then went permanently silent — no write, no error.
                        let ct_chr_now = sh.ct_chr.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        if let Some(ct_chr) = ct_chr_now {
                            // ⛔ THE CIPHERTEXT DOES NOT FIT ONE WRITE EITHER. This wrote all 1088 bytes of the
                            // ML-KEM ciphertext in a single `writeValue`, but ATT caps a write at 512 bytes —
                            // so the merchant received a TRUNCATED ct and its `[u8; 1088]` decaps conversion
                            // could never succeed. Same ceiling that truncated the encapsulation key on the way
                            // out, on the return leg: the two devices paired, exchanged a key, and then the
                            // session silently died with the merchant unable to seal a charge the payer asked
                            // for. Frame it, exactly as the key and the charge already travel.
                            // ⛔ ONE WRITE-WITH-RESPONSE AT A TIME. Issuing all 7 ciphertext frames in a loop
                            // looks like it sends them; CoreBluetooth accepts the first and DROPS the rest, so
                            // the merchant never reassembles a whole ciphertext, never decapsulates, and never
                            // seals a charge. Measured on a real iPhone-to-Mac tap at 16 cm: the session
                            // established and then "the merchant never delivered a charge this payer could
                            // open". This file already paces CELL_UP exactly this way — the ciphertext leg
                            // simply did not, and a burst that is silently truncated looks identical to a
                            // merchant that ignored us.
                            let ct_frames = moneropay::frame(&ct, MPAY_BLE_MTU);
                            eprintln!(
                                "[payer] encaps OK — ciphertext {} bytes -> {} frame(s) queued for the CT characteristic",
                                ct.len(), ct_frames.len()
                            );
                            {
                                let mut q = sh.ct_tx.lock().unwrap_or_else(|e| e.into_inner());
                                q.clear();
                                for frag in ct_frames {
                                    q.push_back(frag);
                                }
                            }
                            // ⛔ DO NOT RE-LOCK `ct_chr` HERE. This block is entered via
                            // `if let Some(ct_chr) = sh.ct_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {`, and Rust keeps that
                            // temporary MutexGuard alive for the WHOLE `if let` body — so locking the same
                            // mutex again on the same thread deadlocks the BLE delegate queue outright. The
                            // assignment was redundant anyway: we are inside this block precisely because
                            // `ct_chr` is already `Some`.
                            //
                            // Measured: the payer logged `encaps OK — ciphertext 1088 bytes -> 7 frame(s)
                            // queued` and then NOTHING — no write, no error, no timeout of its own. Same class
                            // as the merchant-side stall, and just as invisible: a deadlocked delegate queue
                            // looks exactly like a peer that stopped answering.
                            payer_ct_flush(sh, &peripheral);
                        }
                    }
                    Err(e) => payer_finish(sh, Err(format!("encaps: {}", e))),
                }
            } else if uuid == moneropay::MONEROPAY_CHR_CHARGE {
                sh.frames.lock().unwrap_or_else(|e| e.into_inner()).push(val);
                let frames = sh.frames.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if let Ok(sealed) = moneropay::reassemble(&frames) {
                    let session = match *sh.session.lock().unwrap_or_else(|e| e.into_inner()) {
                        Some(s) => s,
                        None => return,
                    };
                    match moneropay::open(&session, &nonce_for(1), &sealed) {
                        Ok(charge_bytes) => {
                            let rssi = *sh.rssi_dbm.lock().unwrap_or_else(|e| e.into_inner());
                            let distance_cm = moneropay::estimated_distance_cm(
                                rssi,
                                moneropay::MONEROPAY_RSSI_AT_1M_DBM,
                            );
                            payer_finish(
                                sh,
                                Ok(PayerOutcome { charge_bytes, rssi_dbm: rssi, distance_cm }),
                            );
                        }
                        Err(_) => { /* not all frames yet; wait for more */ }
                    }
                }
            } else if uuid == moneropay::MONEROPAY_CHR_CELL_DOWN {
                // A node-cell fragment from the merchant's node → reassemble into our node's inbound bridge.
                // Independent of the charge/ack payment flow — it just keeps the two DAGs converging while the
                // tap connection is up (fail-open: a bad fragment doesn't complete a cell, which re-gossips).
                let _ = sh.cell_pump.lock().unwrap_or_else(|e| e.into_inner()).on_fragment(&val);
            }
        }

        // A notify subscription changed state. When CELL_DOWN notifications are on, the node-cell leg is
        // live in both directions → start pumping our outbound cells up.
        #[unsafe(method(peripheral:didUpdateNotificationStateForCharacteristic:error:))]
        fn did_update_notif_state(
            &self,
            _peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            _error: Option<&NSError>,
        ) {
            let sh = &self.ivars().shared;
            let ud = unsafe { characteristic.UUID().data() };
            let uuid = nsdata_to_vec(&ud);
            if uuid == moneropay::MONEROPAY_CHR_CELL_DOWN {
                let on = unsafe { characteristic.isNotifying() };
                sh.cell_ready.store(on, Ordering::SeqCst);
                if on {
                    payer_cell_flush(sh);
                }
            }
        }

        // A CELL_UP write-with-response completed → clear the in-flight gate and issue the next fragment.
        // One outstanding write at a time is the correct pacing (CoreBluetooth's own completion drives it),
        // so we never flood the write queue and never drop a fragment to congestion.
        #[unsafe(method(peripheral:didWriteValueForCharacteristic:error:))]
        fn did_write_value(
            &self,
            _peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            _error: Option<&NSError>,
        ) {
            let sh = &self.ivars().shared;
            let ud = unsafe { characteristic.UUID().data() };
            let uuid = nsdata_to_vec(&ud);
            if uuid == moneropay::MONEROPAY_CHR_KEM_CT {
                eprintln!("[payer] the merchant ACKED a ciphertext frame — sending the next");
                // One ciphertext frame landed — send the next. Without this chain the burst above would be
                // truncated by CoreBluetooth and the handshake would stall with no error anywhere.
                sh.ct_write_inflight.store(false, Ordering::SeqCst);
                payer_ct_flush(sh, _peripheral);
            } else if uuid == moneropay::MONEROPAY_CHR_CELL_UP {
                sh.cell_write_inflight.store(false, Ordering::SeqCst);
                payer_cell_flush(sh);
            }
        }
    }
);

// ── Payer node-cell pump (runs entirely on the CB serial queue) ─────────────────────────────────────
/// One tick of the payer's node-cell pump, on the CB queue: drain up to `CELL_BURST` outbound cells into
/// fragments, then (re)start the one-at-a-time write chain if it isn't already running.
fn payer_cell_tick(sh: &Arc<PayerShared>) {
    if !sh.cell_ready.load(Ordering::SeqCst) {
        return; // link not fully up yet — leave cells in the node bridge (bounded, drop-oldest)
    }
    {
        let mut pump = sh.cell_pump.lock().unwrap_or_else(|e| e.into_inner());
        let mut tx = sh.cell_tx.lock().unwrap_or_else(|e| e.into_inner());
        // Drive at most what the queue can hold. `drive_outbound` takes only what it is asked for, so the
        // rest stays in the pump and goes out next tick — back-pressure, not loss.
        let burst = CELL_BURST.min(room_for(&tx));
        pump.drive_outbound(burst, |f| {
            let _ = push_bounded(&mut tx, f);
        });
    }
    payer_cell_flush(sh);
}

/// Issue the next ML-KEM ciphertext frame iff no write is in flight — the same one-at-a-time pacing
/// `payer_cell_flush` uses, because CoreBluetooth honours exactly one write-with-response per characteristic
/// and silently discards a burst.
fn payer_ct_flush(sh: &Arc<PayerShared>, peripheral: &CBPeripheral) {
    // Entry itself is a fact worth recording: two separate re-entrant-guard deadlocks have already stopped
    // this function from being REACHED, and from the outside that is indistinguishable from it running and
    // choosing not to write.
    eprintln!("[payer] ct_flush entered");
    let chr = match sh.ct_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(c) => c,
        None => {
            eprintln!("[payer] cannot write the ciphertext — the CT characteristic was never discovered");
            return;
        }
    };
    if sh
        .ct_write_inflight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        // Rule 5: this return is silent, and it is the ONLY remaining exit on the ciphertext path that never
        // says anything. If the flag is stuck set — because a write was issued that the peripheral never
        // acknowledged — every later flush lands here forever and no ciphertext is ever sent.
        eprintln!("[payer] ct_flush SKIPPED — a ciphertext write is already marked in flight");
        return;
    }
    let (frag, left) = {
        let mut q = sh.ct_tx.lock().unwrap_or_else(|e| e.into_inner());
        match q.pop_front() {
            Some(f) => {
                let n = q.len();
                (f, n)
            }
            None => {
                sh.ct_write_inflight.store(false, Ordering::SeqCst);
                eprintln!("[payer] ciphertext fully written — no frames left to send");
                return;
            }
        }
    };
    eprintln!("[payer] writing a ciphertext frame ({} bytes, {left} left after this)", frag.len());
    unsafe {
        peripheral.writeValue_forCharacteristic_type(
            &*nsdata_from(&frag),
            &chr,
            objc2_core_bluetooth::CBCharacteristicWriteType::WithResponse,
        )
    };
}

/// Issue the next CELL_UP fragment iff no write is in flight (one-at-a-time, paced by didWriteValue). The
/// chain re-arms itself from `did_write_value`; the timer tick also calls this so a fresh batch starts.
fn payer_cell_flush(sh: &Arc<PayerShared>) {
    let periph = match sh.peripheral.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(p) => p,
        None => return,
    };
    let chr = match sh.cell_up_chr.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(c) => c,
        None => return,
    };
    // Only one outstanding write-with-response at a time.
    if sh
        .cell_write_inflight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // a write is already in flight — did_write_value will chain the next
    }
    let frag = match sh.cell_tx.lock().unwrap_or_else(|e| e.into_inner()).pop_front() {
        Some(f) => f,
        None => {
            sh.cell_write_inflight.store(false, Ordering::SeqCst); // nothing to send — release the gate
            return;
        }
    };
    unsafe {
        periph.writeValue_forCharacteristic_type(
            &*nsdata_from(&frag),
            &chr,
            objc2_core_bluetooth::CBCharacteristicWriteType::WithResponse,
        )
    };
}

/// Schedule the payer's recurring cell tick on the CB serial `queue`. Re-arms every `CELL_TICK_MS` until
/// `cell_run` clears — the same guaranteed-liveness driver as the merchant, on the central side.
fn arm_payer_cell_timer(queue: DispatchRetained<DispatchQueue>, sh: Arc<PayerShared>) {
    if !sh.cell_run.load(Ordering::SeqCst) {
        return;
    }
    let q_next = queue.clone();
    let _ = queue.after(cell_tick_delay(), move || {
        payer_cell_tick(&sh);
        arm_payer_cell_timer(q_next, sh);
    });
}

/// Tap to pay: bring up a MoneroPay central, scan, range-gate, complete the ML-KEM handshake and OPEN
/// the sealed charge from the nearest in-range merchant over real BLE. Returns the plaintext charge
/// (which the caller then runs through the unchanged verify → Face ID → wallet_pos_pay flow), plus the
/// measured RSSI + distance. Times out if no in-range merchant completes the handshake.
pub fn pay_nearby(timeout: Duration) -> Result<PayerOutcome, String> {
    bt_authorization_gate()?;
    let (done_tx, done_rx) = mpsc::channel::<Result<PayerOutcome, String>>();
    let shared = Arc::new(PayerShared {
        central: Mutex::new(None),
        not_terminals: Mutex::new(std::collections::HashSet::new()),
        ek_frames: Mutex::new(Vec::new()),
        ct_tx: Mutex::new(std::collections::VecDeque::new()),
        ct_write_inflight: std::sync::atomic::AtomicBool::new(false),
        session: Mutex::new(None),
        frames: Mutex::new(Vec::new()),
        rssi_dbm: Mutex::new(0),
        discovered_rssi: Mutex::new(None),
        peripheral: Mutex::new(None),
        ct_chr: Mutex::new(None),
        done_tx: Mutex::new(Some(done_tx)),
        // Node-cell pump bridging THIS device's in-process node to the tap connection (central side).
        cell_pump: Mutex::new(BleCellPump::new(ble_bridge(), MPAY_BLE_MTU)),
        cell_tx: Mutex::new(VecDeque::new()),
        cell_up_chr: Mutex::new(None),
        cell_ready: AtomicBool::new(false),
        cell_write_inflight: AtomicBool::new(false),
        cell_run: AtomicBool::new(true),
    });
    let shared_thread = shared.clone();
    std::thread::spawn(move || {
        let queue = dispatch2::DispatchQueue::new("org.monerousd.moneropay.payer", None);
        let ivars = PayerIvars { shared: shared_thread.clone() };
        let this = PayerDelegate::alloc().set_ivars(ivars);
        let delegate: Retained<PayerDelegate> = unsafe { msg_send![super(this), init] };
        let proto = ProtocolObject::from_ref(&*delegate);
        // Stored below so a non-terminal peripheral can be dropped and the scan restarted.
        let mgr: Retained<CBCentralManager> = unsafe {
            CBCentralManager::initWithDelegate_queue(
                CBCentralManager::alloc(),
                Some(proto),
                Some(&queue),
            )
        };
        *delegate.ivars().shared.central.lock().unwrap_or_else(|e| e.into_inner()) = Some(mgr.clone());
        // Start the recurring node-cell pump on the same serial queue that owns the delegate (guaranteed-live
        // convergence over the tap; no cross-thread radio access).
        arm_payer_cell_timer(queue.clone(), shared_thread.clone());
        // Keep the manager + delegate alive until the payment completes or times out.
        std::thread::sleep(timeout + Duration::from_millis(500));
        shared_thread.cell_run.store(false, Ordering::SeqCst);
        unsafe { mgr.stopScan() };
        drop(mgr);
        drop(delegate);
    });
    match done_rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => match *shared.discovered_rssi.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(rssi) => {
                // ⛔⛔⛔ THIS IS THE TIMEOUT BRANCH — IT MUST NOT BLAME DISTANCE BY DEFAULT.
                //
                // Reaching here means the charge exchange did not COMPLETE in time, for whatever reason. The
                // message asserted one specific cause — "outside the tap range, hold the wallets closer" —
                // no matter how close the devices actually were. Measured on a real iPhone-to-Mac tap: a
                // merchant discovered at RSSI -49 dBm, about 12 cm away, told to move closer to get inside
                // 40 cm. That is why holding the phones together never helped: the advice was unrelated to
                // the fault, so the user could only ever fail at it.
                //
                // Say what was observed. In range means the radio found each other and the EXCHANGE stalled;
                // out of range is the only case where moving closer is the actual remedy.
                let dist = moneropay::estimated_distance_cm(rssi, moneropay::MONEROPAY_RSSI_AT_1M_DBM);
                if moneropay::within_tap_range(rssi, moneropay::MONEROPAY_RSSI_AT_1M_DBM) {
                    Err(format!(
                        "a MoneroPay merchant was IN TAP RANGE (RSSI {rssi} dBm, ~{dist:.0} cm) but the charge \
                         exchange did not complete before the timeout — the devices found each other, so this \
                         is not a distance problem; the merchant never delivered a charge this payer could open"
                    ))
                } else {
                    Err(format!(
                        // The device this reading came from was never confirmed to be a MoneroPay terminal —
                        // identity is only known after connecting. Say what was actually observed.
                        "the nearest Bluetooth device was {rssi} dBm (~{dist:.0} cm) and no MoneroPay terminal \
                         answered in tap range. If your terminal is right here, it is most likely not \
                         advertising a charge — weaker than the \
                         {} dBm a tap requires — hold the wallets closer",
                        moneropay::MONEROPAY_MIN_RSSI_DBM
                    ))
                }
            }
            None => Err("no MoneroPay merchant in tap range (timed out)".into()),
        },
    }
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════
// PROOF: two-endpoint real-radio loopback in ONE process (merchant advertises ⇄ payer taps).
// ══════════════════════════════════════════════════════════════════════════════════════════════════

/// Real-radio self-test: advertise `charge_bytes` as a merchant, then tap-to-pay it as a payer, both
/// over the actual Bluetooth radio on this machine. Proves the whole MoneroPay OTA loop end to end
/// (advertise → discover → range-gate → ML-KEM → sealed charge → reassemble → open) and asserts the
/// opened plaintext byte-matches what the merchant sealed. Returns a report for the UI.
pub fn selftest_loopback(charge_bytes: Vec<u8>, timeout: Duration) -> Result<serde_json::Value, String> {
    bt_authorization_gate()?;
    let merchant = start_merchant(charge_bytes.clone())?;
    // Give the peripheral a moment to power on + begin advertising before the central scans.
    std::thread::sleep(Duration::from_millis(600));

    // ⛔ FAIL FAST AND SAY WHY WHEN THE RADIO IS UNAUTHORIZED.
    //
    // If macOS has not granted Bluetooth, CoreBluetooth reports `.unauthorized` and the peripheral never
    // powers on. The scan below then runs its FULL timeout and reports "no MoneroPay merchant in tap range"
    // — which tells the user their tap partner was too far away, when in fact this device's radio was never
    // allowed to turn on. Thirty seconds of waiting, then a misleading answer, for a problem one click fixes.
    {
        let st = merchant.status_json();
        let powered = st.get("powered_on").and_then(|v| v.as_bool()).unwrap_or(false);
        let err = st.get("last_error").and_then(|v| v.as_str()).unwrap_or("");
        if !powered && err.to_lowercase().contains("not powered on") {
            merchant.stop();
            return Err(format!(
                "Bluetooth is not available to this app — macOS has not granted it permission, so the radio \
                 never turned on. Open the wallet from Finder and allow Bluetooth when prompted, or enable it \
                 under System Settings › Privacy & Security › Bluetooth. (radio state: {err})"
            ));
        }
    }
    let outcome = pay_nearby(timeout);
    let mstatus = merchant.status_json();
    merchant.stop();
    // ⚠️ CARRY THE MERCHANT'S STATE INTO THE ERROR. `outcome?` used to discard `mstatus` on exactly the path
    // where it is the only thing that explains anything: "no merchant in tap range" is compatible with the
    // radio being off, advertising never starting, or a permission refusal — and those need opposite fixes.
    // The status was already computed one line above and thrown away.
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => return Err(format!("{e} — merchant state at timeout: {mstatus}")),
    };
    let matches = outcome.charge_bytes == charge_bytes;
    Ok(serde_json::json!({
        "ok": matches,
        "opened_len": outcome.charge_bytes.len(),
        "sealed_len": charge_bytes.len(),
        "charge_matches": matches,
        "rssi_dbm": outcome.rssi_dbm,
        "distance_cm": outcome.distance_cm,
        "in_tap_range": true,
        "merchant": mstatus,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
// ⭐⭐ THE TAP PROTOCOL'S FOUR STEPS, WITHOUT THE RADIO — so two PROCESSES can run a tap over any carrier.
//
// `ble_tap_pay`'s missing proof is the JOIN (e2e register): no test carried a charge over the tap protocol, paid
// it, and then asked the MERCHANT's node whether the payment settled. The radio cannot run in a test process
// (macOS keys Bluetooth TCC to an app identity), so these are the SAME steps `start_merchant` / `pay_nearby`
// run — ML-KEM key out, ciphertext back, the charge sealed under the session with `nonce_for(1)`, every crossing
// `moneropay::frame`d at `MPAY_BLE_MTU` and `reassemble`d by the other side — as pure functions over frames. The
// caller carries the frames between the two devices (a test relays them over the two processes' stdio); each
// side keeps its own ephemeral key or session in its own memory, exactly as a device does during a tap.
//
// What this does NOT claim: the radio's physical layer (advertising, GATT, RSSI range physics) — proven on
// hardware separately. Nothing here reports an RSSI or a distance, because nothing here measured one. Nothing is
// written anywhere: the frames are returned to the caller.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

/// The merchant's side of one tap, held in the merchant's memory between its two steps.
pub struct TapMerchant {
    dk: moneropay::DecapsKey,
    charge_bytes: Vec<u8>,
}

/// The payer's side of one tap: the session it derived from the merchant's key.
pub struct TapPayer {
    session: [u8; 32],
}

/// MERCHANT step 1: a fresh ML-KEM key for this tap; returns the key's frames for the air.
pub fn tap_merchant_begin(charge_bytes: Vec<u8>) -> Result<(TapMerchant, Vec<Vec<u8>>), String> {
    let (ek_bytes, dk) = moneropay::merchant_new_kem().map_err(|e| e.to_string())?;
    Ok((TapMerchant { dk, charge_bytes }, moneropay::frame(&ek_bytes, MPAY_BLE_MTU)))
}

/// PAYER step 1: reassemble the merchant's key, encapsulate; returns the ciphertext's frames for the air.
pub fn tap_payer_encaps(ek_frames: &[Vec<u8>]) -> Result<(TapPayer, Vec<Vec<u8>>), String> {
    let ek = moneropay::reassemble(ek_frames).map_err(|e| format!("reassemble the merchant's key: {e}"))?;
    let (ct, session) = moneropay::payer_encaps(&ek).map_err(|e| format!("encaps: {e}"))?;
    Ok((TapPayer { session }, moneropay::frame(&ct, MPAY_BLE_MTU)))
}

/// MERCHANT step 2: reassemble the payer's ciphertext, derive the session, seal the charge under it; returns the
/// sealed charge's frames for the air.
pub fn tap_merchant_seal(m: &TapMerchant, ct_frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let ct = moneropay::reassemble(ct_frames).map_err(|e| format!("reassemble the payer's ciphertext: {e}"))?;
    let session = moneropay::merchant_decaps(&m.dk, &ct).map_err(|e| format!("decaps: {e}"))?;
    let sealed = moneropay::seal(&session, &nonce_for(1), &m.charge_bytes);
    Ok(moneropay::frame(&sealed, MPAY_BLE_MTU))
}

/// PAYER step 2: reassemble and open the sealed charge. A tampered or truncated crossing is refused by
/// `reassemble` / `open` — never opened into something else.
pub fn tap_payer_open(p: &TapPayer, charge_frames: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let sealed = moneropay::reassemble(charge_frames).map_err(|e| format!("reassemble the sealed charge: {e}"))?;
    moneropay::open(&p.session, &nonce_for(1), &sealed).map_err(|e| format!("open the sealed charge: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ THE TAP'S FOUR STEPS CARRY A CHARGE BETWEEN TWO SIDES THAT SHARE ONLY FRAMES.
    ///
    /// Merchant and payer each keep their own state (`TapMerchant` / `TapPayer`) and see only the frames the
    /// other put on the air, at the tap MTU. The payer opens exactly the bytes the merchant sealed. TAMPER: one
    /// flipped byte anywhere in the sealed charge on the air is refused, never opened into something else; and a
    /// payer holding ANOTHER tap's session cannot open this charge.
    /// TWO-PARTY-REVIEWED: the two sides are the two parties and hold no shared state; the two-PROCESS journey
    /// (these steps relayed over two wallets' stdio, the charge paid, the merchant's node read) is the
    /// real-node pin `a_charge_carried_over_the_tap_protocol_is_paid_and_the_merchants_node_holds_it`.
    #[test]
    fn the_tap_steps_carry_a_charge_between_two_sides_that_share_only_frames() {
        let charge = br#"{"v":1,"to":"addr","atomic":50000000,"memo":"MUSD-charge-v1|tap-join"}"#.to_vec();
        let (m, ek_frames) = tap_merchant_begin(charge.clone()).expect("the merchant begins a tap");
        assert!(ek_frames.len() > 1, "the ML-KEM key must need framing at the tap MTU, or no crossing is exercised");
        let (p, ct_frames) = tap_payer_encaps(&ek_frames).expect("the payer encapsulates on the reassembled key");
        let charge_frames = tap_merchant_seal(&m, &ct_frames).expect("the merchant seals under the derived session");
        assert_eq!(tap_payer_open(&p, &charge_frames).expect("the payer opens"), charge, "exactly the sealed bytes");
        let mut bad = charge_frames.clone();
        let last = bad.len() - 1;
        let n = bad[last].len();
        bad[last][n - 1] ^= 1;
        assert!(tap_payer_open(&p, &bad).is_err(), "an altered charge on the air must be refused, never opened");
        let (other, _) = tap_payer_encaps(&tap_merchant_begin(charge).expect("a second tap").1).expect("encaps");
        assert!(tap_payer_open(&other, &charge_frames).is_err(), "a charge opens only under its own tap's session");
    }

    /// ⛔ A PAYMENT FRAME MUST NEVER BE SILENTLY DROPPED.
    ///
    /// `push_bounded` evicts the OLDEST frame once the queue is full. A sealed charge is split across
    /// frames, so losing one does not degrade the tap — it makes the charge unreassemblable, and the payer
    /// sees a tap that simply does nothing. Worse, the drop is invisible: nothing returns an error, nothing
    /// logs, and the queue looks healthy.
    ///
    /// This is the same class as a window or a cap: bounded state bought by DISCARDING data. The bound is
    /// correct — unbounded queues are their own failure — but the response to a full queue must be
    /// back-pressure the sender can see, never a silent eviction.
    #[test]
    fn a_full_frame_queue_never_silently_discards_a_payment_frame() {
        use std::collections::VecDeque;
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        // Fill well past the cap with identifiable frames.
        let total = 600usize;
        // Offer only what the queue has room for, exactly as the real callers now do.
        for i in 0..total {
            let room = room_for(&q);
            if room == 0 {
                break; // back-pressure: the caller stops and retries next tick
            }
            assert!(
                push_bounded(&mut q, (i as u32).to_le_bytes().to_vec()),
                "a push within the queue's stated room must never be refused"
            );
        }
        let total = q.len(); // everything we were ABLE to queue must still be there
        assert_eq!(total, CELL_TX_CAP, "the queue should be exactly full at this point");
        let oldest_before = q.front().cloned().expect("a full queue has a front");

        // ⛔ THE DECISIVE CASE. A caller that offers one MORE frame than there is room for must be REFUSED —
        // the frame stays with the sender and goes out next tick. If instead the oldest is evicted, a sealed
        // charge loses a frame and can never reassemble, with nothing reported anywhere.
        //
        // ⚠️ Respecting `room_for` above is not enough on its own: a test that only ever offers what fits
        // never reaches the eviction path at all. Verified by tamper — restoring `pop_front()` leaves such a
        // test GREEN, which is how a silent data-drop survives a passing suite.
        let refused = push_bounded(&mut q, u32::MAX.to_le_bytes().to_vec());
        assert!(
            !refused,
            "a push into a FULL queue must be refused so the sender retries — returning true means the frame \
             was accepted by evicting someone else's"
        );
        assert_eq!(
            q.front().cloned(),
            Some(oldest_before),
            "the OLDEST frame must survive an over-offer. It did not, so the queue evicted a payment frame: \
             the charge it belonged to can never reassemble and the tap fails silently."
        );
        assert_eq!(q.len(), CELL_TX_CAP, "and the queue must not have grown past its cap");
        // Which frames survived?
        let survived: Vec<u32> = q
            .iter()
            .filter_map(|f| f.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())))
            .collect();
        let first_surviving = survived.first().copied().unwrap_or(0);
        assert_eq!(
            survived.len(),
            total,
            "the queue holds {} of {total} frames — {} payment frames were DISCARDED, and the earliest \
             surviving frame is #{first_surviving}. A sealed charge split across frames cannot reassemble \
             once any frame is gone, so the payer's tap fails with nothing reported anywhere.",
            survived.len(),
            total - survived.len()
        );
    }

}
