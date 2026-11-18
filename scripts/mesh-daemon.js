#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/**
 * scripts/mesh-daemon.js — STANDALONE block-gossip mesh node.
 *
 * Runs ONLY the libp2p mesh (publisher + subscriber + fetch + DHT +
 * ACK) — no Ion Swap backend, no bridge dispatch, no database. The
 * goal is mesh VPS-independence: any host can run this daemon and
 * keep the mesh alive even if the canonical Ion Swap backend host
 * goes down.
 *
 * Cross-bootstrap topology:
 *   VPS ($MONEROUSD_VPS_HOST): runs ion-backend (which includes its own
 *     mesh-coordinator). Listens on tcp/4720, ws/4721.
 *   Edge ($MONEROUSD_EDGE_HOST): runs THIS daemon. Bootstraps to VPS multi-addr.
 *   Community nodes: run THIS daemon. Bootstrap to VPS, edge, or both.
 *
 * If VPS dies, the edge daemon keeps publishing/relaying. Subscribers
 * continue receiving via the edge. The "no single point of failure"
 * property is the cross-bootstrap network — not the daemon itself.
 *
 * PRIVACY POSTURE
 * ───────────────
 * The operator directive is "private by default, no disable button,
 * no IPs anywhere." That target requires libp2p to dial through the
 * Tor SOCKS5 transport AND complete its noise+yamux upgrade dance
 * over the SOCKS5-tunnelled stream. Today the transport at
 * `backend/mesh/tor-socks-transport.js` does the SOCKS5 handshake
 * correctly but returns a raw socket wrapper that libp2p's
 * connection-upgrader rejects. Phase 5.C (a focused 1-2 day sprint)
 * completes that integration; until then this daemon's privacy
 * posture is:
 *
 *   ALREADY DEFAULT-ON (no env opt-out):
 *     - Ephemeral libp2p peer-id every boot for COMMUNITY nodes.
 *       Breaks cross-session correlation. A bootstrap-relay
 *       operator may OPT IN to a stable identity by setting
 *       `BRIDGE_MESH_PRIVKEY_FILE` (rotation by restart still works;
 *       this is opt-in for "well-known-relay" semantics only).
 *     - .onion announce-addr when Tor + HiddenService present —
 *       other Tor-aware peers can already dial us through it.
 *
 *   NOT YET SHIPPED (Phase 5.C):
 *     - libp2p Tor SOCKS5 outbound transport with proper
 *       connection-upgrader integration. Tracked in
 *       `docs/NODE-SYNC-AUDIT-LOG.md` (Phase 5.C entry).
 *
 * Until 5.C lands, the daemon is best-effort: probes Tor + surfaces
 * .onion via `announce` when available, but listens on /ip4/ and
 * accepts /ip4/ bootstrap so the mesh stays functional. This is NOT
 * a privacy opt-out — it's honest unfinished work.
 *
 * Required env:
 *   BLOCK_GOSSIP_DAEMON_URL          local USDmd RPC, e.g. http://127.0.0.1:17750/json_rpc
 *   BRIDGE_BOOTSTRAP_RELAY_MULTIADDRS comma-separated multi-addrs of OTHER mesh nodes
 *
 * Optional env:
 *   BRIDGE_MESH_LISTEN               override default listen addrs
 *                                    (default: /ip4/0.0.0.0/tcp/4720
 *                                              /ip4/0.0.0.0/tcp/4721/ws)
 *   BRIDGE_MESH_PRIVKEY_FILE         path to a 32-byte hex seed
 *                                    (mode 0600). When present the
 *                                    peer-id is stable across
 *                                    restarts — opt-in for
 *                                    bootstrap-relay nodes whose
 *                                    multi-addr others reference.
 *                                    When absent the peer-id is
 *                                    ephemeral per boot (the
 *                                    community-node privacy default).
 *   BLOCK_GOSSIP_TOR_SOCKS           Tor SOCKS5 proxy URL (default
 *                                    socks5://127.0.0.1:9050)
 *   BLOCK_GOSSIP_HS_HOSTNAME_FILE    Tor HiddenService hostname file
 *                                    (default /var/lib/tor/monerousd-mesh/hostname)
 *   BLOCK_GOSSIP_ACK_DISABLE         '1' disables the ACK+retry layer for tests
 *
 * Usage:
 *   node scripts/mesh-daemon.js
 */
'use strict';

// ── Node 20 compatibility shim ────────────────────────────────────
// `Promise.withResolvers` is a Node 22+ standard. The current libp2p
// stack uses it via `it-queue` → `mortice` → `@libp2p/peer-store`.
// On Node 20 the daemon crashes at startup; install a minimal
// polyfill before any libp2p import resolves.
if (typeof Promise.withResolvers !== 'function') {
  Promise.withResolvers = function withResolvers() {
    let resolve, reject;
    const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
    return { promise, resolve, reject };
  };
}

import { createValidatorMeshNode } from '../backend/bridge/validator-mesh-node.js';
import { startBootstrapAutoRedial } from '../backend/bridge/bootstrap-auto-redial.js';
import fs from 'node:fs';

// Parse comma-separated multi-addr list (matches mesh-coordinator-node.js).
function parseMultiaddrList(raw, fallback) {
  if (!raw) return fallback;
  return String(raw).split(',').map((s) => s.trim()).filter(Boolean);
}

function readPrivkeySeedOrNull(path) {
  // Mirrors backend/bridge/mesh-coordinator-node.js::readPrivkeySeedOrNull —
  // accepts hex (64 chars, optional 0x prefix). Raw-binary 32-byte files
  // are NOT supported (operator should `xxd -p` to convert).
  if (!path) return null;
  try {
    const raw = fs.readFileSync(path, 'utf8').trim();
    const hex = raw.startsWith('0x') ? raw.slice(2) : raw;
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      console.warn(
        `[mesh-daemon] BRIDGE_MESH_PRIVKEY_FILE=${path} present but not 32-byte hex; ` +
        `using ephemeral keypair (peer-id rotates per restart)`,
      );
      return null;
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  } catch (err) {
    console.warn(
      `[mesh-daemon] could not read BRIDGE_MESH_PRIVKEY_FILE=${path}: ${err.message} — ` +
      `using ephemeral keypair`,
    );
    return null;
  }
}

async function main() {
  const daemonRpcUrl = process.env.BLOCK_GOSSIP_DAEMON_URL || 'http://127.0.0.1:17750/json_rpc';

  // ── 1. Best-effort Tor probe ──
  // Mirrors mesh-coordinator-node.js: log warning + continue when Tor
  // isn't reachable. The mesh still works without Tor; full privacy
  // hardening lands with Phase 5.C.
  const { probeTorTransport } = await import('../backend/mesh/tor-socks-transport.js');
  const torProbe = await probeTorTransport({
    proxyUrl: process.env.BLOCK_GOSSIP_TOR_SOCKS || 'socks5://127.0.0.1:9050',
  });
  let ourOnion = null;
  if (torProbe.active) {
    console.log(`[mesh-daemon] Tor SOCKS5 reachable at ${torProbe.proxy.host}:${torProbe.proxy.port}`);
    try {
      const hsPath = process.env.BLOCK_GOSSIP_HS_HOSTNAME_FILE
        || '/var/lib/tor/monerousd-mesh/hostname';
      const raw = fs.readFileSync(hsPath, 'utf8').trim();
      if (/^[a-z2-7]{56}\.onion$/i.test(raw)) {
        ourOnion = raw;
        console.log(`[mesh-daemon] hidden-service .onion = ${ourOnion}`);
      } else {
        console.warn('[mesh-daemon] HS hostname file malformed; continuing without .onion announce');
      }
    } catch (err) {
      console.warn(`[mesh-daemon] cannot read .onion identity (${err.message}); continuing without .onion announce`);
    }
  } else {
    console.warn(
      `[mesh-daemon] Tor not reachable (${torProbe.reason}). ` +
      'Mesh comes up without .onion announce — install Tor + enable HiddenService for full privacy hardening (Phase 5.C).',
    );
  }

  // ── 2. Listen / announce / bootstrap addrs ──
  const listen = parseMultiaddrList(
    process.env.BRIDGE_MESH_LISTEN,
    ['/ip4/0.0.0.0/tcp/4720', '/ip4/0.0.0.0/tcp/4721/ws'],
  );
  const announce = ourOnion ? [`/onion3/${ourOnion.replace(/\.onion$/i, '')}:4720`] : [];
  const bootstrappers = parseMultiaddrList(
    process.env.BRIDGE_BOOTSTRAP_RELAY_MULTIADDRS,
    [],
  );

  // ── 3. Peer-id derivation ──
  // Opt-in stable identity for bootstrap-relay operators; ephemeral
  // default for community nodes. Stable identity is a "well-known
  // relay" property — your .onion / IP is already public; the
  // libp2p peer-id mirrors that.
  const privateKeyRaw32 = readPrivkeySeedOrNull(process.env.BRIDGE_MESH_PRIVKEY_FILE);
  if (privateKeyRaw32) {
    console.log('[mesh-daemon] libp2p peer-id = stable (loaded from BRIDGE_MESH_PRIVKEY_FILE)');
  } else {
    console.log('[mesh-daemon] libp2p peer-id = ephemeral (rotates per boot — community-node default)');
  }

  // TIER 1.3 — libp2p mesh role is operator-controlled via
  // BRIDGE_MESH_ROLE env. Default 'peer' (safe for any community
  // node). Public-IP / .onion-reachable bootstrap hosts opt in to
  // 'relay' explicitly via their env file so they serve DHT queries
  // + circuit-relay-v2 reservations on behalf of NAT'd peers.
  //
  // NAMING: this libp2p TRANSPORT role is orthogonal to bonded
  // MoneroUSD-validator status. The libp2p role string used to be
  // 'validator' (deprecated) and was renamed to 'peer' to eliminate
  // confusion with the bonded-validator concept tracked separately
  // via BridgeValidatorBond.dsol + bridge_validators DB.
  const meshRole = (process.env.BRIDGE_MESH_ROLE === 'relay')
    ? 'relay'
    : 'peer';
  console.log(`[mesh-daemon] libp2p role=${meshRole} (transport-layer; orthogonal to bonded-validator status)`);

  const node = await createValidatorMeshNode({
    role:    meshRole,
    listen,
    announce,
    torProxyUrl: torProbe.active && torProbe.proxy
      ? `socks5://${torProbe.proxy.host}:${torProbe.proxy.port}`
      : null,
    bootstrappers,
    privateKeyRaw32,
  });
  console.log(
    `[mesh-daemon] libp2p UP — peer-id=${node.peerId.toString()} ` +
    `listen=[${listen.join(', ')}] announce=[${announce.join(', ')}] ` +
    `bootstrappers=${bootstrappers.length}`,
  );

  // ── 4. Dial bootstrap peers ──
  if (bootstrappers.length > 0) {
    const { multiaddr } = await import('@multiformats/multiaddr');
    for (const ma of bootstrappers) {
      try {
        await node.dial(multiaddr(ma));
        console.log(`[mesh-daemon] connected to bootstrap: ${ma}`);
      } catch (err) {
        console.warn(
          `[mesh-daemon] bootstrap dial failed (continuing): ${ma} — ${err.message}`,
        );
      }
    }
  }

  // ── 4b. TIER 1.4 — auto-redial loop ──
  // Periodic reconnect so a peer restart on the other side heals
  // automatically. Without this, the operator had to manually
  // restart this daemon whenever the VPS came back online — the
  // exact failure mode that gated every libp2p@2.x verification
  // cycle until the loop was added.
  const stopAutoRedial = startBootstrapAutoRedial({
    libp2pNode:    node,
    bootstrappers,
    logTag:        '[mesh-daemon]',
  });

  // ── 5. Start the mesh modules ──
  const { startBlockGossipPublisher, publisherStats } =
    await import('../backend/mesh/block-gossip-publisher.js');
  const { startBlockGossipSubscriber } =
    await import('../backend/mesh/block-gossip-subscriber.js');
  const { startBlockFetchProtocol } =
    await import('../backend/mesh/block-fetch-protocol.js');
  const { startBlockDhtProvider } =
    await import('../backend/mesh/block-dht-provider.js');
  const { startBlockGossipAck } =
    await import('../backend/mesh/block-gossip-ack.js');

  await startBlockGossipPublisher({ libp2pNode: node, daemonRpcUrl });
  const networkId = publisherStats().networkId;
  if (!networkId) {
    console.error('[mesh-daemon] FATAL: publisher could not resolve networkId from local USDmd');
    process.exit(1);
  }

  await startBlockGossipAck({ libp2pNode: node, networkId });
  await startBlockFetchProtocol({ libp2pNode: node, networkId, daemonRpcUrl });
  await startBlockDhtProvider({ libp2pNode: node, daemonRpcUrl });
  await startBlockGossipSubscriber({ libp2pNode: node, networkId, daemonRpcUrl });

  // ── 5b. TIER 2.1 — relay-candidate gossip ──
  // Every node that's relay-eligible (reputation score above the
  // floor) broadcasts a signed RELAY_HEARTBEAT every 60s. Receivers
  // maintain a locally-sorted candidate list (cascading-failover
  // ordering). Pre-this, the /v1/mesh/peers endpoint could only see
  // DIRECT gossipsub neighbors because libp2p's getSubscribers is
  // one-hop-only; this topic makes the FULL mesh chain-wide
  // observable.
  const { startRelayCandidateGossip } =
    await import('../backend/mesh/relay-candidate-gossip.js');
  await startRelayCandidateGossip({ libp2pNode: node, networkId });

  // ── 5c. TIER 2.3 — malicious-tip alerts ──
  // Each detection in block-gossip-subscriber (BAD_SIG, FUTURE_HEIGHT)
  // publishes a signed alert here. Receivers independently corroborate
  // by replaying the validation locally — confirmed-malicious peers
  // earn -50; false alerts cost the detector -25.
  const { startMaliciousTipAlerts, ALERT_CODES } =
    await import('../backend/mesh/malicious-tip-alerts.js');
  const { verifySig, getLocalCanonicalTip } =
    await import('../backend/mesh/block-gossip-subscriber.js');
  const { MAX_FUTURE_HEIGHT_OFFSET } =
    await import('../backend/mesh/block-gossip-constants.js');

  const localVerifier = (offendingMessage, violationCode) => {
    try {
      switch (violationCode) {
        case ALERT_CODES.BAD_SIG: {
          // Replay the same sig check our subscriber does on accept.
          // If the sig is genuinely bad → corroborated. If it actually
          // verifies → the detector is wrong (or has a different
          // verifier) → false alert.
          return { corroborated: !verifySig(offendingMessage) };
        }
        case ALERT_CODES.FUTURE_HEIGHT: {
          const localTip = getLocalCanonicalTip();
          if (localTip < 0) return { corroborated: null, reason: 'no_local_tip' };
          return {
            corroborated: offendingMessage.height > localTip + MAX_FUTURE_HEIGHT_OFFSET,
          };
        }
        case ALERT_CODES.FETCH_3X_FAIL:
          // Independent re-fetch is too expensive in the verifier
          // closure (would block other alert handling). Leave
          // indeterminate; future work in Tier 2.5 can add a
          // bounded-rate background re-verification path.
          return { corroborated: null, reason: 'fetch_replay_deferred' };
        default:
          return { corroborated: null, reason: 'unknown_code' };
      }
    } catch (_) {
      return { corroborated: null, reason: 'verifier_error' };
    }
  };
  await startMaliciousTipAlerts({ libp2pNode: node, networkId, localVerifier });

  // ── 6. Graceful shutdown ──
  async function shutdown(signal) {
    console.log(`[mesh-daemon] received ${signal}, shutting down`);
    try {
      if (stopAutoRedial) {
        try { stopAutoRedial(); } catch (_) { /* tolerate */ }
      }
      const stopFns = await Promise.all([
        import('../backend/mesh/malicious-tip-alerts.js').then((m) => m.stopMaliciousTipAlerts),
        import('../backend/mesh/relay-candidate-gossip.js').then((m) => m.stopRelayCandidateGossip),
        import('../backend/mesh/block-gossip-subscriber.js').then((m) => m.stopBlockGossipSubscriber),
        import('../backend/mesh/block-dht-provider.js').then((m) => m.stopBlockDhtProvider),
        import('../backend/mesh/block-fetch-protocol.js').then((m) => m.stopBlockFetchProtocol),
        import('../backend/mesh/block-gossip-ack.js').then((m) => m.stopBlockGossipAck),
        import('../backend/mesh/block-gossip-publisher.js').then((m) => m.stopBlockGossipPublisher),
      ]);
      for (const fn of stopFns) await fn();
      await node.stop();
    } catch (err) {
      console.warn(`[mesh-daemon] shutdown error (continuing): ${err.message}`);
    }
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  console.log('[mesh-daemon] all modules started — mesh is live');
}

main().catch((err) => {
  console.error(`[mesh-daemon] FATAL: ${err.stack || err}`);
  process.exit(1);
});
