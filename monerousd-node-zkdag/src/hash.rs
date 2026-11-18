// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Content hashing for the DAG. `Hash32` is a blake3 digest used for block ids, merkle roots,
//! and state/frontier commitments. blake3 gives 256-bit preimage/collision resistance — sound
//! against classical and (Grover/collision-bounded) quantum attack — and is fast. This is the
//! STRUCTURAL content hash only; the PoUW hash (PQ-PoUW preimage + the #73 non-outsourceable
//! bind) is computed in the consensus layer, not here.

use serde::{Deserialize, Serialize};

/// A 32-byte blake3 content digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Default for Hash32 {
    /// The all-zero digest — the natural default for an empty/absent root (genesis, no-carry).
    fn default() -> Self {
        Hash32::ZERO
    }
}

impl Hash32 {
    /// The all-zero digest (used for empty/absent roots at genesis).
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    /// blake3 over `bytes`.
    pub fn hash(bytes: &[u8]) -> Hash32 {
        Hash32(*blake3::hash(bytes).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild a digest from a received 32-byte wire slice (e.g. a `TipBeacon` tip id). Returns `None`
    /// for any other length (fail-closed — a malformed request never constructs a bogus id).
    pub fn from_slice(bytes: &[u8]) -> Option<Hash32> {
        <[u8; 32]>::try_from(bytes).ok().map(Hash32)
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

}

impl core::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}…", &self.to_hex()[..16])
    }
}

impl core::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
