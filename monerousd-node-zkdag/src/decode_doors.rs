// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! Protocol: MonerousD — THE DECODE DOORS: every production decoder of OUTSIDE bytes, callable by name.
//!
//! B1 (ii), 2026-10-22 (readiness R1 instruments; the hole scanner's "decode of outside bytes no fuzzer reaches").
//! A decoder of bytes the node did not write — a request body, a file on disk another process may have written, an
//! object a peer served — is a door hostile bytes walk through, and a door nobody has pushed hostile bytes through is
//! unmeasured (a panic, an unbounded allocation, a hang). This module names each such decoder ONCE, as a thin call
//! into the production function that owns it (never a copy of the decode: a copy would measure the copy), so that the
//! two instruments that push bytes through them reach the SAME code:
//!
//! * the cargo-fuzz targets under `fuzz/fuzz_targets/` (one per door, libFuzzer on nightly, run bounded by
//!   `scratchpad/verify/fuzz_doors.sh`; the corpus under `fuzz/corpus/<door>/` is kept, a crash input lands under
//!   `fuzz/artifacts/<door>/` and becomes a committed RED-first pin);
//! * the in-process replay pin `harness::fuzz::decode_doors_tests::every_decode_door_of_outside_bytes_fails_closed_…`
//!   (seeded by `SIM_SEED`, farm-listed), which replays the corpus and the artifacts plus seeded hostile bytes and
//!   judges every door fail-closed — no panic, no hang — and writes one `decode-fuzz` coverage row per green door;
//!   the hole scanner (`harness::holes`) closes a decode site by that row on the current source, mapping each site to
//!   its door by the decoded TYPE in the site's own text (`surface_census::decode_door_for`).
//!
//! THE NEW-DOOR CHECKLIST (AGENTS.md §9.6) does not apply: nothing here is an ingress path. `drive` reads the bytes it
//! is handed, returns a verdict and drops the value; no node state is read or written, no file is touched, and no route
//! or wire message reaches it. A door that needs a path reads bytes, not a path (the file read stays in production code).
//! Every door is O(input bytes): one decode of the bytes handed in, nothing read from the chain or the node.

/// The JSON document door: `serde_json::Value` from outside bytes (every JSON request body the routes read through
/// `rpc_http::json_str_field` / `json_bool_field` / `json_num_field`, the wallet's node-answer and BLE-charge reads).
pub const JSON_VALUE: &str = "json-value";
/// The checkpoint door: the boot's snapshot read (`persist::decode_checkpoint` — the current schema, then every frozen
/// pre-fork layout named by `pre_fork_door_diagnosis`, then the fold-record trailer).
pub const SNAPSHOT_FILE: &str = "snapshot-file";
/// The `@name` registry file (`names::parse_registry_bytes`).
pub const NAME_REGISTRY_FILE: &str = "name-registry-file";
/// Tor's guard-sample document (`arti_transport::guard_sample_counts`).
pub const TOR_GUARDS_DOC: &str = "tor-guards-doc";
/// A served nullifier witness set (`Vec<nf_sparse::CompressedCopath>`, postcard: the wallet's exact read and the tree's
/// `decode_exact`).
pub const COMPRESSED_COPATH_VEC: &str = "compressed-copath-vec";

/// A price relay's HTTP body (`price_relay::parse`, every relay network's convention) — bytes a validator fetches from an
/// outside exchange service over Tor and reads before any signature or quorum judges them (lane stable 2026-11-01: the
/// hole scanner's last node-side decode site with no door).
pub const PRICE_RELAY_ANSWER: &str = "price-relay-answer";

/// The mix layer's doors (`pqmix::drive_door`, docs/PQ-MIX-LAYER-SPEC-20261106.md §7): a packet, a signed record, a link frame,
/// the framing inside a delivered packet, and a carrier address. Every byte of each comes from a stranger.
pub const MIX_PACKET: &str = "mix-packet";
pub const MIX_RECORD: &str = "mix-record";
pub const MIX_FRAME: &str = "mix-frame";
pub const MIX_INNER: &str = "mix-inner";
pub const MIX_CARRIER: &str = "mix-carrier";

/// Every door, in the order the instruments drive them.
pub const DOORS: &[&str] = &[
    JSON_VALUE,
    SNAPSHOT_FILE,
    NAME_REGISTRY_FILE,
    TOR_GUARDS_DOC,
    COMPRESSED_COPATH_VEC,
    PRICE_RELAY_ANSWER,
    MIX_PACKET,
    MIX_RECORD,
    MIX_FRAME,
    MIX_INNER,
    MIX_CARRIER,
];

/// What a door answered: the bytes decoded as the type (`Accepted`) or were refused (`Refused`). Both are fail-closed;
/// the instruments judge a PANIC or a HANG, never the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Refused,
}

fn verdict(accepted: bool) -> Verdict {
    if accepted {
        Verdict::Accepted
    } else {
        Verdict::Refused
    }
}

/// Push `bytes` through `door`. `None` names an unknown door (a door name no production decoder stands behind).
pub fn drive(door: &str, bytes: &[u8]) -> Option<Verdict> {
    match door {
        JSON_VALUE => Some(json_value(bytes)),
        SNAPSHOT_FILE => Some(verdict(std::hint::black_box(crate::persist::decode_checkpoint(bytes)).is_ok())),
        NAME_REGISTRY_FILE => Some(verdict(std::hint::black_box(crate::names::parse_registry_bytes(bytes)).is_some())),
        #[cfg(feature = "arti-onion")]
        TOR_GUARDS_DOC => Some(verdict(
            std::str::from_utf8(bytes).ok().and_then(|raw| std::hint::black_box(crate::arti_transport::guard_sample_counts(raw))).is_some(),
        )),
        COMPRESSED_COPATH_VEC => {
            // the wallet reads a served witness set through the same exact decoder (lib.rs, `chain_object::decode_exact`)
            let exact = std::hint::black_box(crate::chain_object::decode_exact::<Vec<crate::nf_sparse::CompressedCopath>>(bytes)).is_some();
            Some(verdict(exact))
        }
        PRICE_RELAY_ANSWER => {
            // every network's convention parses the same outside bytes: a body is accepted when any of them reads a price
            let any = [crate::price_relay::Network::Bisq, crate::price_relay::Network::Haveno]
                .into_iter()
                .any(|n| std::hint::black_box(crate::price_relay::parse(n, bytes)).is_some());
            Some(verdict(any))
        }
        #[cfg(feature = "arti-onion")]
        MIX_PACKET | MIX_RECORD | MIX_FRAME | MIX_INNER | MIX_CARRIER => {
            crate::pqmix::drive_door(door, bytes).map(|accepted| verdict(std::hint::black_box(accepted)))
        }
        _ => None,
    }
}

fn json_value(bytes: &[u8]) -> Verdict {
    let mut accepted = std::hint::black_box(serde_json::from_slice::<serde_json::Value>(bytes)).is_ok();
    if let Ok(body) = std::str::from_utf8(bytes) {
        // the three field readers every JSON route body goes through (one representative field each: the string reader
        // parses the whole document whatever the field, the bool and number readers scan for the key)
        accepted |= std::hint::black_box(crate::rpc_http::json_str_field(body, "name")).is_some();
        accepted |= std::hint::black_box(crate::rpc_http::json_bool_field(body, "by_ordinal")).is_some();
        accepted |= std::hint::black_box(crate::rpc_http::json_num_field(body, "from_height")).is_some();
    }
    verdict(accepted)
}
