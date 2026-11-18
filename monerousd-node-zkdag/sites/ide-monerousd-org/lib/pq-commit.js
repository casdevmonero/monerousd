// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// lib/pq-commit.js — THE IDE's PREVIEW CONFIDENTIAL PRIMITIVES, POST-QUANTUM (2026-10-28, hole scanner T1/T2).
//
// Replaces lib/pedersen.js + lib/bulletproofs-plus-plus.js + lib/vendor/noble: curve-based Pedersen commitments and
// Bulletproofs++ inside the IDE's local DSOL simulator — pre-quantum curve crypto, a Monero-era holdover whose "byte-
// compatible with the chain's canonical backend" claim had been stale since the PQ chain (the node's confidential
// primitives are Poseidon2 commitments proven by the WHIR gate; nothing a browser preview computes is consensus).
//
// These are HASH-BASED (SHA-256 — the same first-party lib/sha256-sync.js the compiler hashes bundles with): binding and
// hiding against a quantum adversary (Grover halves the bits; a 256-bit preimage stays out of reach), and they keep the
// SAME byte widths the VM's opcodes always pushed (32-byte commitment, 576-byte range PREVIEW, 32-byte nullifier), so a
// contract's preview trace keeps its shape. A preview is a preview: the node's gate is what verifies a deployed contract.
import { sha256Sync } from './sha256-sync.js';

export const COMMITMENT_BYTES = 32;
export const RANGE_PREVIEW_BYTES = 576;
export const NULLIFIER_BYTES = 32;

function utf8(s) { return new TextEncoder().encode(String(s)); }
function concat(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function u64le(v) {
  const b = new Uint8Array(8);
  let x = BigInt(v) & ((1n << 64n) - 1n);
  for (let i = 0; i < 8; i++) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
}
function blindingBytes(r) {
  const raw = r instanceof Uint8Array ? r : utf8(r == null ? '' : r);
  return sha256Sync(concat(utf8('MUSD-DSOL-PREVIEW-BLIND-V1'), raw));
}

/** `C = H(domain ‖ v ‖ H(blinding))` — 32 bytes; hiding by the blinding, binding by the hash. */
export function commit(v, r) {
  return sha256Sync(concat(utf8('MUSD-DSOL-PREVIEW-COMMIT-V1'), u64le(v), blindingBytes(r)));
}

/** The 576-byte preview shape `commitment ‖ transcript`: a deterministic hash stream over the commitment. It is a
 * PREVIEW of the width a range proof occupies in a contract's trace — the chain's range proof is the WHIR gate's. */
export function rangeProof(v, r) {
  const c = commit(v, r);
  const out = new Uint8Array(RANGE_PREVIEW_BYTES);
  out.set(c, 0);
  let off = COMMITMENT_BYTES;
  let ctr = 0;
  while (off < RANGE_PREVIEW_BYTES) {
    const blk = sha256Sync(concat(utf8('MUSD-DSOL-PREVIEW-RANGE-V1'), c, u64le(ctr++)));
    const n = Math.min(blk.length, RANGE_PREVIEW_BYTES - off);
    out.set(blk.subarray(0, n), off);
    off += n;
  }
  return out;
}

/** Nullifier bound to `(contractId, secret)` — 32 bytes (the preview's double-spend key). */
export function nullifier(contractId, secret) {
  const sec = secret instanceof Uint8Array ? secret : utf8(secret == null ? '' : secret);
  return sha256Sync(concat(utf8('MUSD-DSOL-NULLIFIER-V1:'), utf8(contractId || ''), sec));
}
