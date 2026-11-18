#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//
// publish-peer-manifest.js — Layer 1 of the no-islanding architecture.
//
// What this does
// ──────────────
// Reads the operator's local USDmd daemon's white-list (peers the
// daemon has handshake-verified against its own network_id in the
// last 7 days), filters to recently-reachable IPs, signs the result
// with the operator's ed25519 key, and writes a Phase-4 wire-format
// manifest ready to commit to GH Pages at
// `casdevmonero/monerousd-ota-manifest:peer-manifest.json`.
//
// Every desktop wallet polls https://update.monerousd.org/peer-manifest.json
// every 30 min (services/seed-manifest-fetcher.js), FROST-verifies the
// signature against the wallet-binary's pinned PEER_MANIFEST public
// key, and feeds the host:port list into the local USDmd daemon's
// --add-priority-node args on next spawn.
//
// Result: a fresh wallet on any network that can reach GH Pages can
// bootstrap into the USDmd P2P mesh even if every hardcoded IP and
// every DNS seed is unreachable. GH Pages availability ≈ 99.95% (the
// same Microsoft CDN that runs every GitHub Pages site on Earth).
//
// Why a DIFFERENT script than publish-seed-manifest.js
// ────────────────────────────────────────────────────
// publish-seed-manifest.js emits a legacy wire format
// `{ signed_body: "<canonical-json-string>", signature, version }`
// that does NOT match what services/seed-manifest-fetcher.js (Phase 4)
// expects. The Phase 4 fetcher reads
// `{ manifest: {...}, signature: "hex..." }` with the manifest body
// embedded as a real JSON object, signature 64-byte ed25519 hex over
// canonicalize(manifest). This script writes that exact shape.
//
// The legacy script is preserved for backward-compat with any older
// flow that depends on it; new flows use THIS script.
//
// Inputs (env)
// ────────────
//   SEED_SIGNING_KEY_PATH  PEM ed25519 private key.
//                          Default: ~/.monerousd/release-keys/seed-signing-key.pem
//   USDMD_RPC_URL          Local USDmd RPC endpoint to read peers from.
//                          Default: http://127.0.0.1:17750
//   EXTRA_SEEDS            Comma-separated host:port list to MERGE with
//                          gossip-discovered. Useful for adding the
//                          edge / community seeds that wouldn't appear
//                          via white-list scan.
//                          Default: $MONEROUSD_VPS_HOST:17749,$MONEROUSD_EDGE_HOST:17749
//   MANIFEST_TTL_BLOCKS    How long until the manifest expires. Default
//                          1024 (~17h at 60s target block time).
//   CURRENT_HEIGHT         Overrides the daemon's reported height for
//                          the published_at_block_height field. Default:
//                          query daemon RPC at boot.
//   OUT_PATH               Where to write the signed manifest.
//                          Default: ~/Desktop/connect/_release/peer-manifest.json
//   MESH_SEEDS_JSON_FILE   Optional path to a JSON file containing an
//                          array of MUMP v1.1 mesh-seed entries to
//                          embed as `manifest.mesh_seeds[]`. Each
//                          entry MUST be shaped
//                          `{mesh_multiaddr: "/onion3/...:port/ws",
//                            role: ["seed","relay"]}` and pass MM-15
//                          (onion-only) validation. IP-/DNS-bearing
//                          entries are rejected before signing so a
//                          compromised composer can't sneak a
//                          clearnet bootstrap into the manifest. The
//                          IPv4 `seeds[]` array (consumed by USDmd
//                          for chain bootstrap) is unaffected — the
//                          two arrays are independent.
//
// Output
// ──────
// Writes a JSON file with the schema:
//   {
//     "manifest": {
//       "version": 1,
//       "published_at_block_height": <uint64>,
//       "expires_at_block_height":   <uint64>,
//       "seeds": [
//         { "id": "IPV4", "addr": "1.2.3.4", "port": 17749 },
//         ...
//       ]
//     },
//     "signature": "<128-hex>"
//   }
//
// AND prints the operator's ed25519 public key as hex. The wallet's
// `build-1261/lib/frost-quorum-verifier.js::GROUP_PUBKEYS.PEER_MANIFEST`
// constant MUST equal this hex; mismatch = signed manifest is
// fail-closed-rejected by every wallet.
//
// Deploy step (after running this)
// ────────────────────────────────
// The output file goes to the GH Pages repo
// `casdevmonero/monerousd-ota-manifest` at path `/peer-manifest.json`.
// The CNAME `update.monerousd.org → casdevmonero.github.io` is already
// in place per memory `reference_ota_routing.md`, so once pushed the
// manifest is live in ~30s.
//

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const os = require('node:os');

// ─── Config ────────────────────────────────────────────────────────

const KEY_PATH = process.env.SEED_SIGNING_KEY_PATH
  || path.join(os.homedir(), '.monerousd', 'release-keys', 'seed-signing-key.pem');
const USDMD_RPC_URL = process.env.USDMD_RPC_URL || 'http://127.0.0.1:17750';
const EXTRA_SEEDS = (process.env.EXTRA_SEEDS
  || `${process.env.MONEROUSD_VPS_HOST}:17749,${process.env.MONEROUSD_EDGE_HOST}:17749`)
  .split(',').map((s) => s.trim()).filter(Boolean);
const MANIFEST_TTL_BLOCKS = parseInt(process.env.MANIFEST_TTL_BLOCKS || '1024', 10);
const OUT_PATH = process.env.OUT_PATH
  || path.join(__dirname, '..', '_release', 'peer-manifest.json');
const MESH_SEEDS_JSON_FILE = process.env.MESH_SEEDS_JSON_FILE || null;

// MUMP v1.1 MM-15 enforcer — must match
// `build-1261/lib/peer-manifest-codec.js::validateMeshMultiaddr`
// byte-for-byte. Duplicated here (not imported) so the publisher has
// zero require-path coupling to the wallet repo. The wallet's
// validator is the canonical one; if you change one, change both.
function validateMeshMultiaddr(addr) {
  if (typeof addr !== 'string' || !addr.startsWith('/')) return false;
  const parts = addr.split('/');
  let hasOnion3 = false;
  for (let i = 1; i < parts.length; i++) {
    const proto = parts[i];
    if (proto === 'onion3') { hasOnion3 = true; i += 1; continue; }
    if (proto === 'ip4' || proto === 'ip6' || proto === 'dns4'
        || proto === 'dns6' || proto === 'dnsaddr' || proto === 'dns'
        || proto === 'onion') {
      return false;
    }
  }
  return hasOnion3;
}

// Load + validate the optional MUMP mesh-seed entries from disk.
// Returns null when no file is configured; returns a validated array
// when one is. Throws (fails the publish) on any malformed entry so a
// silently-stripped mesh-seed never produces a manifest that misses
// half its intended bootstrap surface.
function loadMeshSeedsFromFile(filePath) {
  if (!filePath) return null;
  let raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); }
  catch (e) {
    throw new Error('Cannot read MESH_SEEDS_JSON_FILE at ' + filePath
      + ': ' + e.message);
  }
  let arr;
  try { arr = JSON.parse(raw); }
  catch (e) {
    throw new Error('MESH_SEEDS_JSON_FILE is not valid JSON: ' + e.message);
  }
  if (!Array.isArray(arr)) {
    throw new Error('MESH_SEEDS_JSON_FILE must be a JSON array');
  }
  const out = [];
  for (let i = 0; i < arr.length; i++) {
    const e = arr[i];
    if (!e || typeof e !== 'object') {
      throw new Error('mesh_seeds[' + i + '] is not an object');
    }
    if (typeof e.mesh_multiaddr !== 'string') {
      throw new Error('mesh_seeds[' + i + '].mesh_multiaddr must be a string');
    }
    if (!validateMeshMultiaddr(e.mesh_multiaddr)) {
      throw new Error('mesh_seeds[' + i + '].mesh_multiaddr failed MM-15: '
        + e.mesh_multiaddr + ' (must be /onion3/<base32>:<port>/ws — '
        + 'no /ip4/, /ip6/, /dns*/, or v2 /onion/)');
    }
    const role = Array.isArray(e.role) ? e.role : ['seed'];
    out.push({ mesh_multiaddr: e.mesh_multiaddr, role });
  }
  return out;
}

// Privacy-preserving total. The `seeds` array carries PUBLIC bootstrap
// nodes by IP — those are intentionally exposed so any wallet can
// connect to bootstrap. But the operator may run additional nodes
// whose IPs SHOULD NOT be in the public manifest (home labs, on-call
// Macs, mobile relays). `KNOWN_NODE_COUNT` lets the operator publish
// a TOTAL count without exposing those IPs.
//
// Schema:
//   • manifest.seeds          IP-listed public bootstrap nodes
//   • manifest.known_node_count  operator-asserted total, ≥ seeds.length
//
// Consumers:
//   • wallet's seed-manifest-fetcher reads only `seeds` → IP-anonymized
//     additions don't trigger fake peer-add attempts.
//   • explorer's getNetworkNodes() reads `known_node_count` for the
//     "Known Network Nodes" tile so the displayed total reflects
//     the full operator footprint, not just the bootstrap IPs.
const KNOWN_NODE_COUNT = process.env.KNOWN_NODE_COUNT
  ? parseInt(process.env.KNOWN_NODE_COUNT, 10)
  : null;

const MIN_SEEDS = 1;
const MAX_SEEDS = 64;  // matches addrv2 sanity cap; manifest size stays modest

// ─── Helpers ───────────────────────────────────────────────────────

function isValidIPv4(host) {
  if (typeof host !== 'string') return false;
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const n = parseInt(m[i], 10);
    if (n < 0 || n > 255) return false;
  }
  // Reject private/loopback/multicast/link-local — those are useless
  // as public seeds.
  const a = parseInt(m[1], 10);
  const b = parseInt(m[2], 10);
  if (a === 10) return false;
  if (a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a >= 224) return false; // multicast + reserved
  return true;
}

function isValidPort(port) {
  return Number.isInteger(port) && port > 0 && port < 65536;
}

function rpcGetPeerList(rpcUrl) {
  return new Promise((resolve, reject) => {
    const u = new URL('/get_peer_list', rpcUrl);
    const req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': '2' },
      timeout: 5000,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        body += c;
        if (body.length > 4 * 1024 * 1024) {
          req.destroy(new Error('rpc body > 4MB cap'));
        }
      });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('rpc body not JSON: ' + e.message)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('rpc timeout')));
    req.write('{}');
    req.end();
  });
}

function rpcGetInfo(rpcUrl) {
  return new Promise((resolve, reject) => {
    const u = new URL('/get_info', rpcUrl);
    const req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': '2' },
      timeout: 5000,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error('rpc body not JSON: ' + e.message)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('rpc timeout')));
    req.write('{}');
    req.end();
  });
}

// Canonicalize: recursive sorted-key JSON. Bit-identical to the
// canonicalize used in build-1261/lib/frost-quorum-verifier.js.
function canonicalize(payload) {
  if (payload === null || payload === undefined) {
    throw new Error('canonicalize: null/undefined');
  }
  return Buffer.from(JSON.stringify(payload, sortKeys) + '\n', 'utf8');

  function sortKeys(_k, v) {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = v[k];
      return out;
    }
    return v;
  }
}

// ─── Main ──────────────────────────────────────────────────────────

async function main() {
  console.log('[publish-peer-manifest] starting');

  // 1. Load + parse the operator's signing key.
  let privKeyPem;
  try { privKeyPem = fs.readFileSync(KEY_PATH, 'utf8'); }
  catch (e) {
    throw new Error('Cannot read signing key at ' + KEY_PATH + ': ' + e.message
      + '\nGenerate with: openssl genpkey -algorithm ed25519 -outform PEM -out '
      + KEY_PATH);
  }
  const privKey = crypto.createPrivateKey(privKeyPem);
  if (privKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('Signing key is ' + privKey.asymmetricKeyType + ', expected ed25519');
  }

  // Derive the public key (safe — derived in-process; the raw bytes
  // are 32-byte SPKI suffix per RFC 8410).
  const pubKey = crypto.createPublicKey(privKey);
  const pubDer = pubKey.export({ type: 'spki', format: 'der' });
  const pubHex = pubDer.slice(-32).toString('hex');
  console.log('[publish-peer-manifest] operator pubkey: ' + pubHex);

  // 2. Query the local daemon for peers + current height.
  let info, peerList;
  try {
    [info, peerList] = await Promise.all([
      rpcGetInfo(USDMD_RPC_URL),
      rpcGetPeerList(USDMD_RPC_URL),
    ]);
  } catch (e) {
    throw new Error('Cannot reach local USDmd at ' + USDMD_RPC_URL + ': ' + e.message
      + '\nEither start USDmd locally, or set USDMD_RPC_URL=http://NODE:17750 '
      + 'to publish from a remote node.');
  }
  const currentHeight = parseInt(process.env.CURRENT_HEIGHT, 10)
    || (info && info.height ? Number(info.height) : null);
  if (!Number.isInteger(currentHeight) || currentHeight < 1) {
    throw new Error('current chain height could not be determined');
  }
  console.log('[publish-peer-manifest] current chain height: ' + currentHeight);

  // 3. Build the seed set: gossip-discovered ∪ EXTRA_SEEDS.
  const cutoffSec = Math.floor(Date.now() / 1000) - 7 * 24 * 60 * 60;
  const seedSet = new Map();  // key: "host:port" → { id, addr, port }

  // EXTRA_SEEDS (always included — hardcoded operator floor).
  for (const entry of EXTRA_SEEDS) {
    const m = entry.match(/^([^:]+):(\d+)$/);
    if (!m) {
      console.warn('[publish-peer-manifest] EXTRA_SEEDS entry "' + entry + '" not host:port — skipping');
      continue;
    }
    const host = m[1];
    const port = parseInt(m[2], 10);
    if (!isValidIPv4(host) || !isValidPort(port)) {
      console.warn('[publish-peer-manifest] EXTRA_SEEDS entry "' + entry + '" invalid IPv4/port — skipping');
      continue;
    }
    seedSet.set(host + ':' + port, { id: 'IPV4', addr: host, port });
  }

  // Gossip-discovered peers from white_list (handshake-verified by
  // local daemon — strong trust signal).
  const wl = (peerList && peerList.white_list) || [];
  console.log('[publish-peer-manifest] white_list size: ' + wl.length);
  for (const p of wl) {
    // Monero peer entry shape: { id, ip (uint32 big-endian), port, last_seen }
    if (!p || !Number.isInteger(p.ip) || !Number.isInteger(p.port)) continue;
    if (Number.isInteger(p.last_seen) && p.last_seen < cutoffSec) continue;
    // Decode uint32 IP → dotted-quad. Monero stores the IP in network
    // byte order (the daemon transmits it as a uint32 over the wire
    // and represents it as a network-order BE u32 in the RPC).
    const ipNum = p.ip >>> 0;
    const host = [
      (ipNum >>> 0) & 0xff,
      (ipNum >>> 8) & 0xff,
      (ipNum >>> 16) & 0xff,
      (ipNum >>> 24) & 0xff,
    ].join('.');
    if (!isValidIPv4(host)) continue;
    if (!isValidPort(p.port)) continue;
    seedSet.set(host + ':' + p.port, { id: 'IPV4', addr: host, port: p.port });
    if (seedSet.size >= MAX_SEEDS) break;
  }

  if (seedSet.size < MIN_SEEDS) {
    throw new Error('Only ' + seedSet.size + ' seeds collected; refusing to publish '
      + 'empty manifest. Wait for the daemon to discover peers, or set EXTRA_SEEDS.');
  }
  console.log('[publish-peer-manifest] total seeds: ' + seedSet.size);

  // 4. Build the Phase-4 wire-format manifest.
  const manifest = {
    version: 1,
    published_at_block_height: currentHeight,
    expires_at_block_height: currentHeight + MANIFEST_TTL_BLOCKS,
    seeds: Array.from(seedSet.values()),
  };

  // Optional operator-asserted total node count (privacy-preserving —
  // doesn't enumerate the extra nodes' IPs). When set, the explorer's
  // "Known Network Nodes" tile reads this in preference to seeds.length.
  // Must be ≥ seeds.length (the floor — every public seed counts).
  if (Number.isInteger(KNOWN_NODE_COUNT) && KNOWN_NODE_COUNT > 0) {
    if (KNOWN_NODE_COUNT < seedSet.size) {
      throw new Error('KNOWN_NODE_COUNT (' + KNOWN_NODE_COUNT
        + ') < public seeds count (' + seedSet.size + ') — invalid');
    }
    manifest.known_node_count = KNOWN_NODE_COUNT;
    console.log('[publish-peer-manifest] known_node_count: ' + KNOWN_NODE_COUNT);
  }

  // 4b. MUMP v1.1 — attach optional mesh-seed entries. Each entry is
  // pre-validated against MM-15 (onion-only) so a tampered file
  // can't sneak a clearnet bootstrap past us before signing. The
  // wallet's `peer-manifest-codec.js::parse()` re-validates the same
  // shape after FROST-verify, defense-in-depth.
  const meshSeeds = loadMeshSeedsFromFile(MESH_SEEDS_JSON_FILE);
  if (meshSeeds && meshSeeds.length > 0) {
    manifest.mesh_seeds = meshSeeds;
    console.log('[publish-peer-manifest] mesh_seeds: '
      + meshSeeds.length + ' onion entries');
    for (const e of meshSeeds) {
      console.log('  • ' + e.mesh_multiaddr);
    }
  } else if (MESH_SEEDS_JSON_FILE) {
    // The operator pointed us at a file but it had zero entries.
    // Fail loud rather than emit a manifest that's silently
    // mesh-empty — that would brick MUMP bootstrap.
    throw new Error('MESH_SEEDS_JSON_FILE produced an empty array — '
      + 'refusing to publish a mesh-empty manifest. Inspect '
      + MESH_SEEDS_JSON_FILE + ' and ensure it carries at least '
      + 'one /onion3/...:port/ws entry.');
  }

  // 5. Sign canonicalize(manifest).
  const canonical = canonicalize(manifest);
  const sig = crypto.sign(null, canonical, privKey);
  const sigHex = sig.toString('hex');

  // 6. Self-verify so we never publish an unverifiable manifest.
  const verifyOk = crypto.verify(null, canonical, pubKey, sig);
  if (!verifyOk) {
    throw new Error('self-verify failed — refusing to publish');
  }
  console.log('[publish-peer-manifest] self-verify ok');

  // 7. Emit the combined { manifest, signature } file.
  const output = { manifest, signature: sigHex };
  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(output, null, 2));
  console.log('');
  console.log('Wrote signed manifest to:');
  console.log('  ' + OUT_PATH);
  console.log('');
  console.log('Operator pubkey (pin this in '
    + 'build-1261/lib/frost-quorum-verifier.js::GROUP_PUBKEYS.PEER_MANIFEST):');
  console.log('  ' + pubHex);
  console.log('');
  console.log('Deploy steps:');
  console.log('  1. cd /tmp/monerousd-ota-manifest  # GH Pages repo clone');
  console.log('  2. cp ' + OUT_PATH + ' ./peer-manifest.json');
  console.log('  3. git add peer-manifest.json && git commit -m "peer-manifest: refresh"');
  console.log('  4. git push origin main');
  console.log('');
  console.log('Live URL (5-30s after push):');
  console.log('  https://update.monerousd.org/peer-manifest.json');
}

main().catch((e) => {
  console.error('[publish-peer-manifest] FAILED: ' + e.message);
  process.exit(1);
});
