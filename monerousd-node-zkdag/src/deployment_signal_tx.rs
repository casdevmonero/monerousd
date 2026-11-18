// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ §BR-10 — A VALIDATOR'S DEPLOYMENT SIGNAL (`Class::DeploymentSignal`): the validators' half of bicameral activation.
//!
//! Miners signal with their blocks' version bits; validators signal with this object — the vote key signs (vid, the bits it
//! signals, the window). The fold counts the vid's custody bond toward each Started deployment it names in the open window
//! (`deployment::DeploymentLedger::observe_validator_signal`); a window locks a deployment in only when ≥ 2/3 of custody bond
//! signalled it (and ≥ 90 % of folded blocks). One signal per validator per window: its one-time id rides the lane.
//! Borrowed shape: Ethereum's signed validator messages processed at block processing; the threshold is MonerousD's.
//!
//! §9.6: (1) PoW — the carrying block's; (2) the signature — ML-DSA-65 by the key whose id is `vid`, at admission and the
//! fold; (3) value — none: it moves no note and no weight; (4) replay — `signal_nf(vid, bits, window)` on the lane (one per validator per window, per lane); (5) bounded
//! work — one signature; (6) parity with `Class::FinalityVote` (the other signed validator message): the key is the vid's,
//! the signer must hold a live seat at the fold.

use serde::{Deserialize, Serialize};

/// The signal, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSignalTx {
    pub vid: [u8; 32],
    /// The BIP9 bits it signals (bit `d.bit` for each deployment).
    pub bits: u32,
    /// The window index it signals for: the ledger's open window — `blue_score / reward_epoch_blocks` for the normal lane,
    /// `chain_tick / deployment::FAST_WINDOW_TICKS` for a [`crate::deployment::FAST_SIGNAL`] (A-F60: the emergency hour is
    /// chain time).
    pub window: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 public key (decode refuses any other width).
    pub pubkey: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant — an ML-DSA-65 signature (decode refuses any other width).
    pub sig: Vec<u8>,
}

/// What the vote key signs.
#[must_use]
pub fn signal_msg(vid: &[u8; 32], bits: u32, window: u64) -> Vec<u8> {
    let mut m = crate::pqauth::node_statement(b"MUSD/deployment-signal/v1");
    m.extend_from_slice(vid);
    m.extend_from_slice(&bits.to_le_bytes());
    m.extend_from_slice(&window.to_le_bytes());
    m
}

/// One signal per validator per window — per LANE: a signal carrying `deployment::FAST_SIGNAL` (the emergency window) takes
/// its id under its own domain, so a validator's normal and emergency signals in windows with the same index are two objects,
/// and a normal signal's id is byte-identical to every id before the emergency lane existed. The class is read from the
/// object's own bits, never from a release's table: every node computes the same id.
#[must_use]
pub fn signal_nf(vid: &[u8; 32], bits: u32, window: u64) -> [u8; 32] {
    let domain: &[u8] = if bits & crate::deployment::FAST_SIGNAL != 0 {
        b"MONEROUSD-DEPLOYMENT-SIGNAL-NF-FAST-v1"
    } else {
        b"MONEROUSD-DEPLOYMENT-SIGNAL-NF-v1"
    };
    let mut pre = domain.to_vec();
    pre.extend_from_slice(vid);
    pre.extend_from_slice(&window.to_le_bytes());
    crate::cover::canonical_tag_of_hash(crate::hash::Hash32::hash(&pre).as_bytes())
}

impl DeploymentSignalTx {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::fixed::encode_plain(self)
    }
    #[must_use]
    pub fn wire(&self) -> Vec<u8> {
        crate::chain_object::frame(crate::chain_object::Class::DeploymentSignal, &self.encode())
    }
    /// One canonical encoding, at least one deployment bit (the lane bit alone signals nothing), exact key widths.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<DeploymentSignalTx> {
        let t: DeploymentSignalTx = crate::chain_object::decode_exact(bytes)?;
        (t.bits & !crate::deployment::FAST_SIGNAL != 0 && t.pubkey.len() == crate::theft_tx::ML_DSA_65_PK_BYTES && t.sig.len() == crate::theft_tx::ML_DSA_65_SIG_BYTES)
            .then_some(t)
    }
    /// The stateless half: the key is the vid's and it signed this signal.
    #[must_use]
    pub fn authorised(&self) -> bool {
        crate::pqauth::pubkey_id(&self.pubkey) == self.vid
            && crate::pqauth::ml_dsa_verify(&signal_msg(&self.vid, self.bits, self.window), &self.pubkey, &self.sig)
    }
}

/// What applying a signal at its block's fold did.
#[derive(Debug, PartialEq, Eq)]
pub enum SignalApply {
    NotSignal,
    Applied,
    Refused(&'static str),
}

