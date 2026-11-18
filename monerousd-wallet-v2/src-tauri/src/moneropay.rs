// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// ============================================================================
// MoneroPay — MonerousD's own PQ-secured, range-gated proximity transport for
// in-person tap payments (our own transport, so we never need Apple's NFC path;
// Face ID stays the unlock). It rides a BLE GATT pipe (free Core Bluetooth on
// Apple — iOS + macOS, the SAME radio code; Android's equally-free BLE is the next
// radio binding — NO paid entitlement, NO new hardware), but the SECURITY
// + PRIVACY live in THIS protocol, not the radio. The BLE layer is a dumb byte
// pipe; MoneroPay makes it:
//
//   • APPLE-PAY-TIGHT RANGE (no cross-merchant mixup in a busy building):
//     the merchant advertises at MIN TX power, and the payer RSSI-gates every
//     peer to ~tap distance (`within_tap_range`) — a distant/relayed signal is
//     rejected before anything else happens. On-screen amount+merchant confirm
//     before Face ID is the final backstop, so a mis-range can never auto-pay.
//   • 100% PRIVATE AT EVERY LAYER: the advertisement carries NO identity — only
//     a fresh per-charge random beacon id (rotates every charge, unlinkable);
//     the merchant's real address/amount are NEVER broadcast. After an ML-KEM
//     handshake the ENTIRE charge is ENCRYPTED over the air (not just signed —
//     that is strictly better than NFC, which encrypts nothing). An eavesdropper
//     in radio range learns nothing: not the amount, not who, not linkage.
//   • PQ AT EVERY LAYER: session confidentiality = ML-KEM-768 (fips203);
//     charge authenticity = ML-DSA-65 (the existing `verify_pos_charge`);
//     symmetric AEAD = blake3 XOF keystream + keyed-blake3 MAC (encrypt-then-
//     MAC). Only ML-KEM + ML-DSA + blake3/SHA3 — no classical asymmetric
//     primitive, no pairing, PQ throughout.
//   • SOUND (tamper-tested below): a flipped ciphertext byte, a wrong session
//     key, a corrupted frame, or an out-of-range RSSI are all REJECTED.
//
// WALLET FLOW IS UNCHANGED — this only replaces the "how the charge crosses the
// gap" (NFC -> MoneroPay/BLE). Merchant still `wallet_pos_charge` (ML-DSA-signed),
// payer still Face ID + `wallet_pos_pay` (WHIR spend -> /submit_pq_tx). The
// charge just travels sealed inside a MoneroPay session instead of an NFC blob.
//
// The over-the-air message sequence (both sides speak MoneroPay; BLE only moves bytes):
//   0. Merchant: fresh per-charge ML-KEM-768 (ek_m, dk_m); advertise BeaconAd{ id }.
//      `ek_m` is served on the KEM characteristic (public, unlinkable, reveals nothing).
//   1. Payer: scan, RSSI-gate to tap range, pick the CLOSEST beacon, read ek_m.
//   2. Payer: (ss, ct) = ML-KEM.encaps(ek_m); session = kdf(ss). Send ct (public).
//      Merchant: ss = ML-KEM.decaps(dk_m, ct); session = kdf(ss). Both now share `session`.
//   3. Merchant: SEAL the ML-DSA-signed charge under `session` -> send frames.
//      Payer: reassemble -> OPEN -> verify_pos_charge (ML-DSA) -> show amount -> Face ID.
//   4. Payer: wallet_pos_pay (real WHIR spend -> /submit_pq_tx); SEAL a paid-ack -> merchant.
// Nothing sensitive is EVER in the clear on the radio; each session is one-shot.
// ============================================================================

#![allow(dead_code)] // radio-binding call sites land in the mobile platform layer; the protocol core is complete + tested here.

use fips203::ml_kem_768::{CipherText, EncapsKey, KG};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
// Re-export the ML-KEM decapsulation key type so the BLE radio layer (`moneropay_ble.rs`) can hold the
// merchant's per-session secret (`merchant_new_kem` returns it, `merchant_decaps` consumes it).
pub use fips203::ml_kem_768::DecapsKey;

// ── Fixed MonerousD identifiers for the BLE GATT service (128-bit, MonerousD-unique) ──
/// MoneroPay service UUID the POS advertises while a charge is active (raw 16 bytes; iOS/Android
/// BLE use the UUID directly — a MonerousD-unique id, not a registered SIG short UUID).
pub const MONEROPAY_SERVICE_UUID16: [u8; 16] = *b"MPAY-TAP1-SVC-01";
/// Characteristic the payer READS to fetch the merchant's per-charge ML-KEM encaps key (public).
pub const MONEROPAY_CHR_KEM_EK: [u8; 16] = *b"MPAY-TAP1-KEMEK1";
/// Characteristic the payer WRITES its ML-KEM ciphertext to (establishes the session).
pub const MONEROPAY_CHR_KEM_CT: [u8; 16] = *b"MPAY-TAP1-KEMCT1";
/// Characteristic the merchant NOTIFIES the sealed, framed charge on (payer reassembles + opens).
pub const MONEROPAY_CHR_CHARGE: [u8; 16] = *b"MPAY-TAP1-CHRG01";
/// Characteristic the payer WRITES the sealed paid-ack on.
pub const MONEROPAY_CHR_ACK: [u8; 16] = *b"MPAY-TAP1-ACK-01";
// ── Node convergence rides the SAME tap connection ──
// Two extra characteristics let this one tap-to-pay link ALSO carry the node's onion CELLS, so the two
// devices' GHOSTDAG nodes converge over Bluetooth (tip beacons + #29-DSYNC bundles) alongside the payment
// — no second radio, no separate connection. Each whole unit is a fixed [`usdm_node::net::CELL_SIZE`] onion
// cell fragmented to the ATT MTU; every cell fragments to the IDENTICAL size sequence, so the wire adds NO
// size/volume/timing tell (the constant-rate cover that backs the cell channel keeps it uniform — privacy
// pillar: 100% private at every layer). The cell bytes are already onion-sealed end to end.
/// Characteristic the merchant NOTIFIES node cells DOWN to the payer on (merchant → payer leg).
pub const MONEROPAY_CHR_CELL_DOWN: [u8; 16] = *b"MPAY-TAP1-CELLDN";
/// Characteristic the payer WRITES node cells UP to the merchant on (payer → merchant leg). Together with
/// CELL_DOWN the tap is a full-duplex node transport that the beacon-adopt runtime converges over.
pub const MONEROPAY_CHR_CELL_UP: [u8; 16] = *b"MPAY-TAP1-CELLUP";

pub const MONEROPAY_MAGIC: [u8; 4] = *b"MPAY";
pub const MONEROPAY_VER: u8 = 1;

// ── Range gate: keep it at Apple-Pay tap distance so payments never mix up ──
/// Merchants advertise at the MINIMUM BLE TX power so only a device held right up
/// to the terminal even sees a strong signal. (dBm; -20 is a typical BLE min.)
pub const MONEROPAY_MERCHANT_TX_POWER_DBM: i8 = -20;
/// Calibration reference (DEFAULT constant): the RSSI a payer reads at EXACTLY 1 m from a merchant advertising
/// at the min TX power above. Each merchant advertises its OWN measured `ref_rssi_at_1m_dbm` in the beacon and
/// the payer ranges against THAT; this const is only the pre-pairing default. Recalibrated 2026-07-20 to REAL
/// hardware: a MacBook scanning an iPhone advertising at min power reads ~-57 dBm at a genuine ~15-25 cm tap
/// (laptop radios read materially weaker than the old -30..-45 dBm assumption). Back-solving the log-distance
/// model for that observation puts the 1 m reference near -72 dBm, so a real tap lands well inside the gate.
pub const MONEROPAY_RSSI_AT_1M_DBM: i16 = -72;
/// Hard RSSI floor — reject any beacon weaker than this outright (belt-and-suspenders vs the distance
/// estimate). Sized to REAL hardware: a deliberate laptop↔phone tap reads ~-55..-65 dBm, while a signal from
/// across the room or a long-range relay reads -80 dBm or weaker — so -70 admits a real tap yet still rejects
/// a distant/relayed merchant. (The old -50 wrongly rejected a genuine -57 dBm tap on Mac↔iPhone hardware.)
pub const MONEROPAY_MIN_RSSI_DBM: i16 = -70;
/// The tap-distance ceiling (cm). Beyond this, refuse — this is what stops a payment meant for the terminal
/// you're touching from binding to a merchant across the room, and defeats a long-range BLE relay. Set to the
/// proximity BLE RSSI can ACTUALLY resolve: 40 cm is unambiguously "two devices held together" (a deliberate
/// tap) while an across-room merchant (3 m+) or amplified relay reads far weaker and is rejected. A tighter
/// 15 cm ceiling is below BLE's indoor RSSI resolution and rejected genuine close taps.
pub const MONEROPAY_MAX_TAP_CM: f64 = 40.0;
/// Indoor path-loss exponent for the log-distance model (2.0 free-space .. ~3.0 cluttered).
const MONEROPAY_PATH_LOSS_N: f64 = 2.5;

/// Estimate the peer distance (cm) from a live BLE RSSI reading + the advertiser's calibrated
/// RSSI-at-1m reference (`MONEROPAY_RSSI_AT_1M_DBM`). Log-distance path-loss model.
pub fn estimated_distance_cm(rssi_dbm: i16, ref_rssi_at_1m_dbm: i16) -> f64 {
    let exp = (ref_rssi_at_1m_dbm as f64 - rssi_dbm as f64) / (10.0 * MONEROPAY_PATH_LOSS_N);
    100.0 * 10f64.powf(exp)
}

/// The proximity gate: is this beacon close enough to be a deliberate TAP (not a distant/relayed merchant)?
///
/// ⛔ GATED ON MEASURED RSSI, NEVER ON THE DERIVED DISTANCE. The two used to be ANDed together and they
/// CONTRADICTED each other:
///
///   * the 40 cm ceiling, through the log-distance model, demands RSSI >= -62 dBm
///   * `MONEROPAY_MIN_RSSI_DBM` admits down to -70 dBm
///   * this file's own comment says a deliberate laptop<->phone tap reads "~-55..-65 dBm"
///
/// So the whole band -63..-70 dBm — which the floor admits and the comment calls a GENUINE TAP — was refused
/// by the estimate. Measured on real hardware this session: a Mac and an iPhone sitting adjacent (the phone
/// physically cabled to the Mac) read -65 dBm, which the model turned into 52 cm and refused. That is the
/// reported symptom exactly: "move the device closer no matter how close my device got."
///
/// The estimate is the wrong thing to gate on. Log-distance path loss has ~±100% error at tap range: BLE RSSI
/// saturates near the antenna and swings with orientation, case and body proximity, so centimetres derived
/// from it are an ILLUSTRATION, not a measurement. RSSI itself IS the measurement, and it is what separates a
/// held-together tap (-55..-70) from an across-room or relayed merchant (-80 and weaker).
///
/// `estimated_distance_cm` is kept — it is useful to SHOW a user — but it no longer decides anything.
pub fn within_tap_range(rssi_dbm: i16, _ref_rssi_at_1m_dbm: i16) -> bool {
    rssi_dbm >= MONEROPAY_MIN_RSSI_DBM
}

#[cfg(test)]
mod tap_range_physics_tests {
    use super::*;

    /// ⛔ THE REPORTED SYMPTOM: "move the device closer no matter how close my device got."
    ///
    /// The gate used to AND the RSSI floor with a distance DERIVED from the log-distance model. Those two
    /// disagreed: the 40 cm ceiling demanded RSSI >= -62 dBm while the floor admitted -70, so the band
    /// -63..-70 — which this file's own comment calls a genuine laptop<->phone tap — was always refused.
    /// Measured on real hardware: a Mac and an iPhone sitting adjacent read -65 dBm, which the model turned
    /// into 52 cm and refused.
    ///
    /// TWO-PARTY-REVIEWED: a pure predicate over a MEASURED radio value; the two-device crossing it gates is
    /// covered by tests/ble_two_device.rs. There is no second endpoint inside a threshold function.
    #[test]
    fn a_genuine_held_together_tap_is_admitted_across_the_whole_real_hardware_band() {
        // The band this file documents as a deliberate tap, plus the -65 dBm actually measured Mac<->iPhone.
        for rssi in [-55i16, -57, -60, -62, -65, -68, -70] {
            assert!(
                within_tap_range(rssi, MONEROPAY_RSSI_AT_1M_DBM),
                "a genuine tap at {rssi} dBm must be admitted — the old distance-derived gate refused \
                 everything below -62 dBm while the floor admitted -70, so real taps were told to 'move \
                 closer' when the devices were already touching (measured: -65 dBm, adjacent)"
            );
        }
    }

    /// ...and the gate still REFUSES what it exists to refuse. Relaxing a bound is only safe if the thing it
    /// protects against still fails.
    #[test]
    fn an_across_the_room_or_relayed_merchant_is_still_refused() {
        for rssi in [-71i16, -75, -80, -90, -100] {
            assert!(
                !within_tap_range(rssi, MONEROPAY_RSSI_AT_1M_DBM),
                "a distant/relayed merchant at {rssi} dBm must still be refused — otherwise a payment meant \
                 for the terminal you are touching could bind to one across the room"
            );
        }
    }

    /// The distance estimate is kept for DISPLAY, and it must stay honest about what it is: monotonic in
    /// signal strength, but never the thing that decides.
    #[test]
    fn the_distance_estimate_remains_available_for_display_only() {
        let near = estimated_distance_cm(-55, MONEROPAY_RSSI_AT_1M_DBM);
        let far = estimated_distance_cm(-85, MONEROPAY_RSSI_AT_1M_DBM);
        assert!(near < far, "a stronger signal must read as nearer: {near:.0}cm vs {far:.0}cm");
        // And the value it produces for a REAL adjacent-device reading is the one that used to refuse taps.
        let measured = estimated_distance_cm(-65, MONEROPAY_RSSI_AT_1M_DBM);
        assert!(
            measured > MONEROPAY_MAX_TAP_CM,
            "the -65 dBm measured between ADJACENT devices still estimates {measured:.0}cm, beyond the \
             {MONEROPAY_MAX_TAP_CM}cm ceiling — which is exactly why it must not gate the tap"
        );
    }
}

// ── The advertisement: identity-free, rotates every charge ──
/// What a MonerousD POS broadcasts while a charge is live. It carries NOTHING linkable —
/// just the MoneroPay magic/version and a fresh 16-byte random beacon id (regenerated per
/// charge), plus the merchant's advertised TX power so the payer can range-gate. NO address,
/// NO amount, NO stable id — an observer cannot track a merchant across charges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconAd {
    pub beacon_id: [u8; 16], // fresh CSPRNG per charge — unlinkable
    pub ref_rssi_at_1m_dbm: i16,
}
impl BeaconAd {
    /// 23 bytes: magic(4) ver(1) tx_power(2 LE) beacon_id(16).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(23);
        v.extend_from_slice(&MONEROPAY_MAGIC);
        v.push(MONEROPAY_VER);
        v.extend_from_slice(&self.ref_rssi_at_1m_dbm.to_le_bytes());
        v.extend_from_slice(&self.beacon_id);
        v
    }
    pub fn decode(b: &[u8]) -> Result<BeaconAd, MoneroPayError> {
        if b.len() < 23 || b[0..4] != MONEROPAY_MAGIC || b[4] != MONEROPAY_VER {
            return Err(MoneroPayError::BadBeacon);
        }
        let tx = i16::from_le_bytes([b[5], b[6]]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[7..23]);
        Ok(BeaconAd { beacon_id: id, ref_rssi_at_1m_dbm: tx })
    }
}

/// A fresh, unlinkable 16-byte beacon id (CSPRNG). The merchant advertises THIS as the BLE service UUID for
/// exactly one charge, so a PASSIVE scanner sees only a random id that rotates every charge — never a stable
/// MonerousD service UUID that would fingerprint "a MonerousD tap is happening here", and never a value an
/// observer can link across charges. A genuine MoneroPay merchant is identified only AFTER the payer
/// deliberately connects (by the fixed CHARACTERISTIC UUIDs, visible solely to the device it taps), so the
/// advertisement layer leaks ZERO: not the protocol-in-use, not merchant identity, not cross-charge linkage,
/// not timing tied to MonerousD. This is the metadata-privacy close for the tap layer (privacy pillar: 100%
/// private at EVERY layer). The 128-bit id is collision-safe for the tiny set of nearby live charges.
pub fn fresh_beacon_id() -> [u8; 16] {
    use rand::RngCore as _;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

// ── PQ session: ML-KEM-768 encaps/decaps -> a 32-byte session key ──
/// Merchant side: fresh per-charge ML-KEM-768 keypair. `ek` bytes go on the KEM_EK
/// characteristic (public). Keep `dk` in memory only for this one charge.
pub fn merchant_new_kem() -> Result<(Vec<u8>, DecapsKey), MoneroPayError> {
    let (ek, dk) = KG::try_keygen().map_err(|_| MoneroPayError::Kem)?;
    Ok((ek.into_bytes().to_vec(), dk))
}
/// Payer side: given the merchant's `ek` bytes, produce (ciphertext bytes, session key).
/// Send the ciphertext on KEM_CT; keep the session key local.
pub fn payer_encaps(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), MoneroPayError> {
    let ek_arr: [u8; 1184] = ek_bytes.try_into().map_err(|_| MoneroPayError::Kem)?;
    let ek = EncapsKey::try_from_bytes(ek_arr).map_err(|_| MoneroPayError::Kem)?;
    let (ssk, ct) = ek.try_encaps().map_err(|_| MoneroPayError::Kem)?;
    Ok((ct.into_bytes().to_vec(), session_key(&ssk.into_bytes())))
}
/// Merchant side: given the payer's ciphertext bytes + the charge's `dk`, recover the session key.
pub fn merchant_decaps(dk: &DecapsKey, ct_bytes: &[u8]) -> Result<[u8; 32], MoneroPayError> {
    let ct_arr: [u8; 1088] = ct_bytes.try_into().map_err(|_| MoneroPayError::Kem)?;
    let ct = CipherText::try_from_bytes(ct_arr).map_err(|_| MoneroPayError::Kem)?;
    let ssk = dk.try_decaps(&ct).map_err(|_| MoneroPayError::Kem)?;
    Ok(session_key(&ssk.into_bytes()))
}
/// Bind the raw ML-KEM shared secret to a MoneroPay session key (domain-separated).
/// Public so the BLE radio layer (`moneropay_ble.rs`) can turn the encaps/decaps `shared`
/// secret into the `session` key that `seal`/`open` take.
pub fn session_key(shared: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(shared, b"MoneroPay-v1-session-key").as_bytes()
}

// ── AEAD over the session key: blake3 XOF keystream (encrypt) + keyed-blake3 MAC (auth) ──
// Encrypt-then-MAC — a symmetric, PQ-safe construction. `seal`/`open` protect every OTA
// payload (the charge, the paid-ack) so the radio sees only ciphertext.
const MONEROPAY_TAG_LEN: usize = 16;
fn subkey(session: &[u8; 32], label: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(session, label).as_bytes()
}
fn keystream(session: &[u8; 32], nonce: &[u8; 12], len: usize) -> Vec<u8> {
    let sk = subkey(session, b"MoneroPay-v1-stream");
    let mut h = blake3::Hasher::new_keyed(&sk);
    h.update(nonce);
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}
fn mac(session: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> [u8; MONEROPAY_TAG_LEN] {
    let mk = subkey(session, b"MoneroPay-v1-mac");
    let mut h = blake3::Hasher::new_keyed(&mk);
    h.update(nonce);
    h.update(&(ct.len() as u64).to_le_bytes());
    h.update(ct);
    let full = h.finalize();
    let mut tag = [0u8; MONEROPAY_TAG_LEN];
    tag.copy_from_slice(&full.as_bytes()[..MONEROPAY_TAG_LEN]);
    tag
}
/// Seal a plaintext under the session key + a 12-byte nonce. Output = ciphertext ‖ tag(16).
pub fn seal(session: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let ks = keystream(session, nonce, plaintext.len());
    let mut ct: Vec<u8> = plaintext.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
    let tag = mac(session, nonce, &ct);
    ct.extend_from_slice(&tag);
    ct
}
/// Open a sealed blob. Verifies the MAC (constant-time) BEFORE decrypting; a flipped byte,
/// a wrong key, or a truncated blob all fail with `MoneroPayError::Auth`.
pub fn open(session: &[u8; 32], nonce: &[u8; 12], sealed: &[u8]) -> Result<Vec<u8>, MoneroPayError> {
    if sealed.len() < MONEROPAY_TAG_LEN {
        return Err(MoneroPayError::Auth);
    }
    let (ct, tag) = sealed.split_at(sealed.len() - MONEROPAY_TAG_LEN);
    let expect = mac(session, nonce, ct);
    if !ct_eq(tag, &expect) {
        return Err(MoneroPayError::Auth);
    }
    let ks = keystream(session, nonce, ct.len());
    Ok(ct.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect())
}
/// Constant-time compare (no early-exit timing leak on the tag).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

// ── GATT framing: a BLE ATT MTU is small (~180..512 B); a sealed charge is a few KB.
// Chunk it into ordered frames the receiver reassembles. A blake3 integrity prefix catches
// any dropped/reordered/corrupted frame early (the AEAD MAC is the real gate). ──
const MONEROPAY_FRAME_HDR: usize = 4 + 1 + 2 + 2 + 2; // magic ver seq total plen
/// Split a (already-sealed) message into MTU-sized frames. First 8 bytes of the message hash
/// are prepended so a truncated/garbled reassembly is detected before `open`.
pub fn frame(payload: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let phash = blake3::hash(payload);
    let tag8 = &phash.as_bytes()[..8];
    let mut wrapped = Vec::with_capacity(8 + payload.len());
    wrapped.extend_from_slice(tag8);
    wrapped.extend_from_slice(payload);
    let body = mtu.saturating_sub(MONEROPAY_FRAME_HDR).max(1);
    let total = (((wrapped.len() + body - 1) / body).max(1)) as u16;
    let mut out = Vec::new();
    for (i, chunk) in wrapped.chunks(body).enumerate() {
        let mut f = Vec::with_capacity(MONEROPAY_FRAME_HDR + chunk.len());
        f.extend_from_slice(&MONEROPAY_MAGIC);
        f.push(MONEROPAY_VER);
        f.extend_from_slice(&(i as u16).to_le_bytes());
        f.extend_from_slice(&total.to_le_bytes());
        f.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        f.extend_from_slice(chunk);
        out.push(f);
    }
    out
}
/// Reassemble frames back into the original sealed message. Rejects a bad magic/version,
/// a missing/duplicate/reordered frame, a size mismatch, or a broken integrity prefix.
pub fn reassemble(frames: &[Vec<u8>]) -> Result<Vec<u8>, MoneroPayError> {
    if frames.is_empty() {
        return Err(MoneroPayError::Frame);
    }
    let mut total: Option<u16> = None;
    let mut slots: Vec<Option<Vec<u8>>> = Vec::new();
    for f in frames {
        if f.len() < MONEROPAY_FRAME_HDR || f[0..4] != MONEROPAY_MAGIC || f[4] != MONEROPAY_VER {
            return Err(MoneroPayError::Frame);
        }
        let seq = u16::from_le_bytes([f[5], f[6]]);
        let tot = u16::from_le_bytes([f[7], f[8]]);
        let plen = u16::from_le_bytes([f[9], f[10]]) as usize;
        if f.len() != MONEROPAY_FRAME_HDR + plen {
            return Err(MoneroPayError::Frame);
        }
        match total {
            None => {
                total = Some(tot);
                slots = vec![None; tot as usize];
            }
            Some(t) if t != tot => return Err(MoneroPayError::Frame),
            _ => {}
        }
        let idx = seq as usize;
        if idx >= slots.len() || slots[idx].is_some() {
            return Err(MoneroPayError::Frame); // out-of-range or duplicate
        }
        slots[idx] = Some(f[MONEROPAY_FRAME_HDR..].to_vec());
    }
    let mut wrapped = Vec::new();
    for s in slots {
        wrapped.extend_from_slice(&s.ok_or(MoneroPayError::Frame)?); // a missing frame fails
    }
    if wrapped.len() < 8 {
        return Err(MoneroPayError::Frame);
    }
    let (tag8, payload) = wrapped.split_at(8);
    if tag8 != &blake3::hash(payload).as_bytes()[..8] {
        return Err(MoneroPayError::Frame);
    }
    Ok(payload.to_vec())
}

#[derive(Debug, PartialEq, Eq)]
pub enum MoneroPayError {
    BadBeacon,
    Kem,
    Auth,
    Frame,
}
impl std::fmt::Display for MoneroPayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MoneroPayError::BadBeacon => "MoneroPay: not a MonerousD tap beacon",
            MoneroPayError::Kem => "MoneroPay: ML-KEM session failure",
            MoneroPayError::Auth => "MoneroPay: sealed payload failed authentication",
            MoneroPayError::Frame => "MoneroPay: frame reassembly failed",
        };
        f.write_str(s)
    }
}
impl std::error::Error for MoneroPayError {}

#[cfg(test)]
mod tests {
    use super::*;

    // METADATA PRIVACY (advertisement layer): the merchant advertises a FRESH random beacon id per charge,
    // so a PASSIVE BLE scanner sees only an unlinkable random service UUID — never a stable MonerousD
    // fingerprint, never a value linkable across charges. Adversarial: two charges MUST differ + carry real
    // entropy + never fall back to the static protocol UUID.
    #[test]
    fn beacon_id_rotates_per_charge_and_is_unlinkable() {
        let a = fresh_beacon_id();
        let b = fresh_beacon_id();
        assert_ne!(a, b, "two charges advertise DIFFERENT beacon ids — a passive scanner cannot link charges");
        assert_ne!(a, [0u8; 16], "the beacon id carries real CSPRNG entropy, not a constant/zero fingerprint");
        assert_ne!(
            a, MONEROPAY_SERVICE_UUID16,
            "the advertised id is random per charge, NEVER the static MonerousD service UUID (that would re-add \
             the passive 'MonerousD tap here' fingerprint the rotation exists to remove)"
        );
    }

    // Core Bluetooth requires every characteristic in a service to have a DISTINCT UUID; a copy-paste
    // collision (e.g. CELL_UP == CELL_DOWN, or a cell char == the charge/ack char) would silently break
    // the tap — one write would land on the wrong characteristic. All six must be pairwise distinct, and
    // the two node-cell characteristics must not alias any of the payment characteristics.
    #[test]
    fn moneropay_gatt_characteristic_uuids_are_pairwise_distinct() {
        let chrs = [
            ("KEM_EK", MONEROPAY_CHR_KEM_EK),
            ("KEM_CT", MONEROPAY_CHR_KEM_CT),
            ("CHARGE", MONEROPAY_CHR_CHARGE),
            ("ACK", MONEROPAY_CHR_ACK),
            ("CELL_DOWN", MONEROPAY_CHR_CELL_DOWN),
            ("CELL_UP", MONEROPAY_CHR_CELL_UP),
        ];
        for i in 0..chrs.len() {
            for j in (i + 1)..chrs.len() {
                assert_ne!(
                    chrs[i].1, chrs[j].1,
                    "GATT characteristic UUID collision: {} == {}",
                    chrs[i].0, chrs[j].0
                );
            }
            // A cell characteristic must never equal the advertised (rotating) service-marker constant.
            assert_ne!(chrs[i].1, MONEROPAY_SERVICE_UUID16, "{} aliases the service marker", chrs[i].0);
        }
    }

    // Full PQ handshake -> seal the charge OTA -> payer opens it. This is the happy path.
    #[test]
    fn moneropay_session_roundtrip_seals_charge() {
        let (ek_bytes, dk) = merchant_new_kem().unwrap();
        let (ct_bytes, payer_session) = payer_encaps(&ek_bytes).unwrap();
        let merchant_session = merchant_decaps(&dk, &ct_bytes).unwrap();
        assert_eq!(payer_session, merchant_session, "both sides must derive the same session key");

        let charge = br#"{"amount_usdm":4.50,"address":"cZk...","nonce":"...","sig":"ML-DSA-65..."}"#;
        let nonce = [7u8; 12];
        let sealed = seal(&merchant_session, &nonce, charge);
        assert_ne!(&sealed[..charge.len()], &charge[..], "charge must be ENCRYPTED over the air, not plaintext");
        let opened = open(&payer_session, &nonce, &sealed).unwrap();
        assert_eq!(&opened, charge, "payer recovers the exact signed charge");
    }

    // TAMPER: a flipped ciphertext byte over the air is rejected (AEAD MAC).
    #[test]
    fn moneropay_flipped_byte_rejected() {
        let session = [3u8; 32];
        let nonce = [1u8; 12];
        let mut sealed = seal(&session, &nonce, b"pay 4.50 to merchant");
        sealed[2] ^= 0x01;
        assert_eq!(open(&session, &nonce, &sealed), Err(MoneroPayError::Auth));
    }

    // TAMPER: a wrong session key (eavesdropper who never did the ML-KEM handshake) can't open.
    #[test]
    fn moneropay_wrong_session_key_rejected() {
        let good = [9u8; 32];
        let evil = [8u8; 32];
        let nonce = [2u8; 12];
        let sealed = seal(&good, &nonce, b"confidential charge");
        assert_eq!(open(&evil, &nonce, &sealed), Err(MoneroPayError::Auth));
    }

    // Framing survives MTU chunking; a dropped or corrupted frame is caught.
    #[test]
    fn moneropay_framing_roundtrip_and_loss() {
        let session = [5u8; 32];
        let nonce = [4u8; 12];
        let big = vec![0xABu8; 4096]; // a few-KB sealed charge > one BLE MTU
        let sealed = seal(&session, &nonce, &big);
        let frames = frame(&sealed, 180);
        assert!(frames.len() > 1, "a KB-scale charge must span multiple BLE frames");
        let re = reassemble(&frames).unwrap();
        assert_eq!(re, sealed);
        assert_eq!(open(&session, &nonce, &re).unwrap(), big);

        // Drop a middle frame -> reassembly fails (never silently truncates).
        let mut missing = frames.clone();
        missing.remove(1);
        assert_eq!(reassemble(&missing), Err(MoneroPayError::Frame));

        // Corrupt a frame body -> integrity prefix catches it.
        let mut bad = frames.clone();
        let last = bad.len() - 1;
        *bad[last].last_mut().unwrap() ^= 0xFF;
        assert_eq!(reassemble(&bad), Err(MoneroPayError::Frame));
    }

    // RANGE GATE: a real tap-distance signal passes; an across-the-room / relayed signal is rejected.
    // Recalibrated 2026-07-20 to REAL Mac↔iPhone hardware — the tap RSSI a laptop actually reads is weaker
    // than the old -30..-45 assumption, so the gate now admits the true tap envelope while still fail-closing
    // on a distant/relayed merchant.
    #[test]
    fn moneropay_range_gate_rejects_distant_and_relayed() {
        let cal = MONEROPAY_RSSI_AT_1M_DBM; // the beacon's calibrated RSSI-at-1m reference (default -72)
        // REGRESSION GUARD (the exact field report): a MacBook read an iPhone tap at -57 dBm and the old gate
        // wrongly said "outside tap range — hold closer". A genuine close tap MUST pass now.
        assert!(within_tap_range(-57, cal), "the real Mac↔iPhone tap (-57 dBm, ~25 cm) must pass — the reported bug");
        assert!(within_tap_range(-38, cal), "a phone held right to the terminal (~10 cm) must pass");
        // ADVERSARIAL: a distant/relayed merchant must STILL be rejected — the gate did not just widen to admit all.
        assert!(!within_tap_range(-80, cal), "an across-the-room / relayed merchant (-80 dBm) must be rejected");
        assert!(!within_tap_range(-72, cal), "a full metre away (~1 m, at the 1m reference) is beyond a tap — rejected");
        assert!(!within_tap_range(MONEROPAY_MIN_RSSI_DBM - 1, cal), "below the hard RSSI floor is rejected");
        assert!(estimated_distance_cm(-57, cal) <= MONEROPAY_MAX_TAP_CM, "the -57 dBm tap estimates inside the ceiling");
        assert!(estimated_distance_cm(-38, cal) < estimated_distance_cm(-80, cal), "closer reads stronger (monotone)");
    }

    // The advertisement carries NO identity + rotates: two charges look unlinkable.
    #[test]
    fn moneropay_beacon_is_identity_free_and_encodes() {
        let a = BeaconAd { beacon_id: [1u8; 16], ref_rssi_at_1m_dbm: MONEROPAY_RSSI_AT_1M_DBM };
        let b = BeaconAd { beacon_id: [2u8; 16], ref_rssi_at_1m_dbm: MONEROPAY_RSSI_AT_1M_DBM };
        assert_ne!(a.beacon_id, b.beacon_id, "each charge advertises a fresh, unlinkable id");
        let enc = a.encode();
        assert_eq!(BeaconAd::decode(&enc).unwrap(), a);
        assert_eq!(BeaconAd::decode(b"not-a-moneropay-beacon-x"), Err(MoneroPayError::BadBeacon));
    }
}

#[cfg(test)]
mod session_derivation_is_defined_once_tests {
    use super::*;

    /// ⭐⭐⭐ THE SESSION KEY IS DERIVED EXACTLY ONCE, ON BOTH SIDES.
    ///
    /// TWO-PARTY-REVIEWED: merchant and payer are the two parties, and the assertion is precisely that they
    /// AGREE on a key each computed alone. A tap where they disagree is a charge that can never be opened.
    ///
    /// `payer_encaps` and `merchant_decaps` both already RETURN a session key. The BLE layer then applied
    /// `session_key()` to each result AGAIN — on both sides, so they still matched, and every unit test stayed
    /// green while the real radio path carried a doubly-derived key. That symmetry was luck, not design:
    /// correcting one side alone silently breaks the handshake, which is exactly what nearly happened here.
    ///
    /// This pins the contract so a future caller cannot re-derive without failing: the value these functions
    /// return IS the session key, and hashing it again yields something neither side would agree on.
    #[test]
    fn re_deriving_a_returned_session_key_breaks_agreement() {
        let (ek_bytes, dk) = merchant_new_kem().unwrap();
        let (ct_bytes, payer_session) = payer_encaps(&ek_bytes).unwrap();
        let merchant_session = merchant_decaps(&dk, &ct_bytes).unwrap();
        assert_eq!(
            payer_session, merchant_session,
            "the two sides derived different session keys from one ML-KEM exchange"
        );

        // Applying `session_key` to an ALREADY-derived key must change it — otherwise the double-derivation
        // bug would be invisible and this test would prove nothing.
        let re_derived = session_key(&payer_session);
        assert_ne!(
            re_derived, merchant_session,
            "re-deriving produced the SAME key, so a caller that hashes the result twice would look correct \
             here while sending an unopenable charge over the radio"
        );

        // And a charge sealed under the correct key must NOT open under the re-derived one — the concrete
        // failure a user meets: the tap connects, the payment never completes.
        let charge = br#"{"amount_usdm":1.00}"#;
        let nonce = [3u8; 12];
        let sealed = seal(&merchant_session, &nonce, charge);
        assert!(
            open(&re_derived, &nonce, &sealed).is_err(),
            "a doubly-derived key opened the charge, so the two derivations are interchangeable and nothing \
             above actually constrains the callers"
        );
        assert_eq!(open(&payer_session, &nonce, &sealed).unwrap(), charge, "the correct key opens it");
    }
}

#[cfg(test)]
mod pq_payloads_survive_the_ble_mtu_tests {
    use super::*;

    /// The MTU the BLE layer frames at. Kept in step with `moneropay_ble::MPAY_BLE_MTU`; if that changes and
    /// this does not, the sizes below stop describing the real wire and this test stops meaning anything.
    const BLE_MTU: usize = 180;

    /// ⭐⭐⭐ AN ML-KEM KEY AND CIPHERTEXT MUST SURVIVE THE RADIO INTACT.
    ///
    /// TWO-PARTY-REVIEWED: framing is the merchant→payer and payer→merchant wire itself; the two parties are
    /// the sender that frames and the receiver that reassembles, and the assertion is that the receiver
    /// recovers EXACTLY what was sent. A byte-different key is a session neither side can use.
    ///
    /// Both PQ payloads were sent as ONE attribute operation: the 1184-byte encapsulation key as a static
    /// read-only characteristic value, and the 1088-byte ciphertext as a single `writeValue`. ATT caps an
    /// attribute at 512 bytes, so both were silently TRUNCATED — `payer_encaps` failed its `[u8; 1184]`
    /// conversion on every real tap ("ML-KEM session failure"), and the ciphertext leg would have failed the
    /// same way at `[u8; 1088]`. Two devices paired over the radio and the PQ session could never form.
    ///
    /// These are the exact sizes that broke, at the exact MTU the radio uses.
    #[test]
    fn a_1184_byte_key_and_1088_byte_ciphertext_round_trip_through_framing() {
        for (label, len) in [("ML-KEM-768 encapsulation key", 1184usize), ("ML-KEM-768 ciphertext", 1088usize)] {
            assert!(len > 512, "{label} is {len} bytes — under the 512-byte ATT ceiling this test would prove nothing");
            // Distinct per-byte content, so a dropped or reordered frame cannot pass by looking similar.
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frames = frame(&payload, BLE_MTU);
            assert!(
                frames.len() > 1,
                "{label} framed into a single frame at MTU {BLE_MTU} — it would not have needed framing, so \
                 this case does not exercise the bug"
            );
            let back = reassemble(&frames).expect("a complete frame set must reassemble");
            assert_eq!(back, payload, "{label} did not survive the radio byte-for-byte");
            assert_eq!(back.len(), len, "{label} came back a different length");

            // FAIL CLOSED on an incomplete set. If a missing frame still reassembled, the receiver would hand a
            // short buffer to ML-KEM and the session would fail with no explanation — the original symptom.
            let mut missing = frames.clone();
            missing.remove(frames.len() / 2);
            assert!(
                reassemble(&missing).is_err(),
                "{label} reassembled with a frame MISSING — a partial payload must never be presented as whole"
            );
        }
    }
}

#[cfg(test)]
mod the_whole_wire_exchange_tests {
    use super::*;

    const BLE_MTU: usize = 180; // must track `moneropay_ble::MPAY_BLE_MTU`

    /// ⭐⭐⭐ THE COMPLETE TAP EXCHANGE, WITH EVERY PAYLOAD CROSSING FRAMED — the sequence the radio performs.
    ///
    /// TWO-PARTY-REVIEWED: merchant and payer are the two parties, holding NO shared state — each side is given
    /// only the bytes the other put on the wire, and every crossing goes through `frame`/`reassemble` at the
    /// real MTU. What it does NOT claim is a radio: CoreBluetooth filters a device's own advertisements, so the
    /// physical iPhone⇄Mac tap is proven separately and is not substituted for here.
    ///
    /// This is the test that was missing. Three separate defects lived in these crossings and every existing
    /// unit test stayed green through all of them, because each tested a FUNCTION while the bugs lived in the
    /// wiring between functions:
    ///
    ///   1. the 1184-byte encapsulation key was sent as ONE static attribute value — ATT caps at 512, so
    ///      `payer_encaps` failed its `[u8; 1184]` conversion on every real tap;
    ///   2. the 1088-byte ciphertext was sent as ONE write — the merchant's `[u8; 1088]` decaps never succeeded;
    ///   3. both BLE call sites re-derived an already-derived session key, and matched only by accident.
    ///
    /// Measured on real hardware: an iPhone at 12 cm connected, attempted the session, and died with
    /// "ML-KEM session failure"; after (1) was fixed it reached charge delivery and stalled on (2).
    #[test]
    fn cross_device_a_charge_survives_every_framed_crossing_and_opens() {
        // ── MERCHANT: fresh ML-KEM keypair, key goes out framed ────────────────────────────────────────────
        let (ek_bytes, dk) = merchant_new_kem().unwrap();
        assert_eq!(ek_bytes.len(), 1184, "ML-KEM-768 encapsulation key size changed — the sizes below are stale");
        let ek_on_the_wire = frame(&ek_bytes, BLE_MTU);
        assert!(ek_on_the_wire.len() > 1, "the key must need framing at MTU {BLE_MTU} or this proves nothing");

        // ── PAYER: sees ONLY frames, must reassemble before it can encapsulate ─────────────────────────────
        let ek_recovered = reassemble(&ek_on_the_wire).expect("payer reassembles the key");
        assert_eq!(ek_recovered, ek_bytes, "the key did not survive the crossing byte-for-byte");
        let (ct_bytes, payer_session) = payer_encaps(&ek_recovered).expect("encaps on the reassembled key");
        assert_eq!(ct_bytes.len(), 1088, "ML-KEM-768 ciphertext size changed — the sizes below are stale");
        let ct_on_the_wire = frame(&ct_bytes, BLE_MTU);
        assert!(ct_on_the_wire.len() > 1, "the ciphertext must need framing or crossing (2) is not exercised");

        // ── MERCHANT: sees ONLY frames, must reassemble before it can decapsulate ──────────────────────────
        let ct_recovered = reassemble(&ct_on_the_wire).expect("merchant reassembles the ciphertext");
        assert_eq!(ct_recovered, ct_bytes, "the ciphertext did not survive the crossing byte-for-byte");
        let merchant_session = merchant_decaps(&dk, &ct_recovered).expect("decaps on the reassembled ciphertext");

        // Exactly ONE derivation per side — the accident that hid defect (3).
        assert_eq!(
            payer_session, merchant_session,
            "the two sides hold different session keys, so no charge the merchant seals can ever be opened"
        );

        // ── MERCHANT: seal the charge under the session, stream it framed ──────────────────────────────────
        let charge = br#"{"v":1,"kind":"MUSD-charge-v1","usdm":1.0,"atomic":100000000}"#;
        let nonce = [1u8; 12];
        let sealed = seal(&merchant_session, &nonce, charge);
        assert_ne!(&sealed[..charge.len()], &charge[..], "the charge must be ciphertext on the air");
        let charge_on_the_wire = frame(&sealed, BLE_MTU);

        // ── PAYER: reassemble and open. This is the byte a real user's tap depends on. ─────────────────────
        let sealed_recovered = reassemble(&charge_on_the_wire).expect("payer reassembles the sealed charge");
        let opened = open(&payer_session, &nonce, &sealed_recovered).expect("payer opens the charge");
        assert_eq!(&opened, charge, "the payer recovered different bytes than the merchant sealed");

        // A charge that changes in flight is an ALTERED payment request, not a failed one: a single flipped
        // byte anywhere in the sealed stream must be refused outright, never opened into something else.
        let mut tampered = charge_on_the_wire.clone();
        let last = tampered.len() - 1;
        let b = tampered[last].len() - 1;
        tampered[last][b] ^= 0x01;
        match reassemble(&tampered) {
            Ok(bytes) => assert!(
                open(&payer_session, &nonce, &bytes).is_err(),
                "a charge altered in flight was OPENED — the payer would pay a request the merchant never signed"
            ),
            Err(_) => {} // rejected at the frame layer, equally fail-closed
        }
    }
}
