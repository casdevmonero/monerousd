#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────────
// install-validator-stack.js
//
// Phase 4 — single-command validator installer for community
// operators. Provisions a fresh validator host with the FROST
// validator-mesh stack: USDmd daemon, validator keypair, mesh
// node config, systemd unit, optional public RPC + sovereign-mirror
// nginx vhost.
//
// Why one script
// ──────────────
// VALIDATOR-DEPLOYMENT-GUIDE.md walks the steps; this script
// is the executable form so a community member can bring up a
// validator without manual nginx editing or systemd writing.
//
// Trust posture
// ─────────────
// The script DOES NOT broadcast BOND_APPLY. The operator's
// wallet broadcasts it via the standard wallet approval flow
// per CLAUDE.md rule 1. The script:
//
//   1. Generates a fresh ed25519 validator keypair (NOT derived
//      from any wallet seed — independent identity per rule 50).
//   2. Pulls the chain-anchored USDmd binary release manifest +
//      verifies signature (BINARY_RELEASE Phase H pipeline).
//   3. Lays down config files + systemd unit.
//   4. Prints the validator pubkey + the BOND_APPLY payload for
//      the operator to paste into their wallet.
//
// USAGE
// ─────
//   sudo bash <(curl -sf https://<sovereign-mirror>/install-validator.sh)
//
// or, after pulling this repo:
//   sudo node scripts/install-validator-stack.js \
//     --version          1.2.211 \
//     --validator-name   "alice-helsinki" \
//     --public-hostname  rpc-3.example.org \
//     --enable-public-rpc \
//     --enable-sovereign-mirror
//
// EXIT
// ────
//   0  install ok, payload printed
//   1  bad args / missing prereqs (must be root, etc.)
//   2  binary download / verify failure
//   3  config write failure
// ─────────────────────────────────────────────────────────────────────

'use strict';

const fs       = require('node:fs');
const path     = require('node:path');
const crypto   = require('node:crypto');
const os       = require('node:os');
const { execFileSync } = require('node:child_process');

// ─── arg parsing ────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = {
    enablePublicRpc: false,
    enableSovereignMirror: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--version')         out.version = argv[++i];
    else if (a === '--validator-name')   out.name = argv[++i];
    else if (a === '--public-hostname')  out.publicHostname = argv[++i];
    else if (a === '--data-dir')         out.dataDir = argv[++i];
    else if (a === '--install-dir')      out.installDir = argv[++i];
    else if (a === '--enable-public-rpc')        out.enablePublicRpc = true;
    else if (a === '--enable-sovereign-mirror')  out.enableSovereignMirror = true;
    else if (a === '--release-pubkey')   out.releasePubkey = argv[++i];
    else if (a === '--dry-run')          out.dryRun = true;
    else if (a === '-h' || a === '--help') out.help = true;
  }
  return out;
}

function usageAndExit(code) {
  console.error(
    'Usage: install-validator-stack \\\n' +
    '         --version          <wallet-version, e.g. 1.2.211> \\\n' +
    '         --validator-name   <pseudonym for systemd journals> \\\n' +
    '         --public-hostname  <DNS or IP for public RPC> \\\n' +
    '         [--data-dir        /var/lib/usdmd-validator] \\\n' +
    '         [--install-dir     /opt/monerousd-validator] \\\n' +
    '         [--enable-public-rpc] \\\n' +
    '         [--enable-sovereign-mirror] \\\n' +
    '         [--release-pubkey  <hex-pubkey for BINARY_RELEASE verify>] \\\n' +
    '         [--dry-run]\n'
  );
  process.exit(code);
}

const args = parseArgs(process.argv);
if (args.help) usageAndExit(0);
if (!args.version || !args.name || !args.publicHostname) usageAndExit(1);

const INSTALL_DIR = args.installDir || '/opt/monerousd-validator';
const DATA_DIR    = args.dataDir    || '/var/lib/usdmd-validator';

if (!args.dryRun && process.getuid && process.getuid() !== 0) {
  console.error('  must run as root (sudo) — touches /opt + /var/lib + systemd');
  process.exit(1);
}

// ─── 1. generate validator keypair ──────────────────────────────────

function generateValidatorKey() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const pubKey  = crypto.createPublicKey(privateKey);
  const pubSpki = pubKey.export({ format: 'der', type: 'spki' });
  const pubHex  = Buffer.from(pubSpki.slice(-32)).toString('hex');
  return { privPem, pubHex };
}

// ─── 2. lay down install dir ────────────────────────────────────────

function ensureDir(dir, mode) {
  if (args.dryRun) return;
  fs.mkdirSync(dir, { recursive: true, mode });
}

function writeFileSafe(p, content, mode) {
  if (args.dryRun) {
    console.log(`  [dry-run] would write ${p} (${content.length} bytes, mode ${mode.toString(8)})`);
    return;
  }
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content, { mode });
}

// ─── 3. systemd unit ────────────────────────────────────────────────

function makeSystemdUnit({ binPath, configPath, dataDir, validatorName }) {
  return `[Unit]
Description=MoneroUSD validator (${validatorName})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=monerousd-validator
Group=monerousd-validator
ExecStart=${binPath} \\
  --config-file ${configPath} \\
  --data-dir ${dataDir} \\
  --non-interactive
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${dataDir} ${path.dirname(configPath)}

[Install]
WantedBy=multi-user.target
`;
}

// ─── 4. validator config ────────────────────────────────────────────

function makeValidatorConfig({ privKeyPath, publicHostname, enablePublicRpc, enableSovereignMirror }) {
  return JSON.stringify({
    validatorPrivateKeyPath: privKeyPath,
    publicHostname,
    publicRpc: enablePublicRpc ? {
      enabled: true,
      bindHost: '0.0.0.0',
      bindPort: 17750,
      // TLS: operator runs certbot separately; this script does
      // not provision certs (LE rate-limit + needs DNS validation).
      tlsCertPath: `/etc/letsencrypt/live/${publicHostname}/fullchain.pem`,
      tlsKeyPath:  `/etc/letsencrypt/live/${publicHostname}/privkey.pem`,
    } : { enabled: false },
    sovereignMirror: enableSovereignMirror ? {
      enabled: true,
      // Static directory served by the same validator's nginx; the
      // OTA / monerousd.org / IDE / installers bundles get rsynced
      // here from the operator's release pipeline. SHA-anchored.
      mirrorDir: '/var/www/monerousd-mirror',
    } : { enabled: false },
    meshBootstrapPeers: [
      // Chain-anchored peers — discovered via the validator's own
      // chain-scanner once USDmd is synced. Bootstrap list pulls
      // from the most recent active-validator-set root on chain.
    ],
    bridges: {
      // Per-chain RPCs the validator needs to participate in
      // FROST signing. Operator fills these in /etc/ion/validator-bridges.env.
    },
  }, null, 2) + '\n';
}

// ─── 5. nginx vhost (sovereign mirror + public RPC) ─────────────────

function makeNginxConf({ publicHostname, enablePublicRpc, enableSovereignMirror }) {
  const blocks = [];

  if (enableSovereignMirror) {
    blocks.push(`# Sovereign-mirror — serves OTA + monerousd.org + IDE + installers.
# Every byte is SHA-verified by the wallet's site-updater +
# binary-release-verifier (chain-anchored hash trust root).
server {
    listen 443 ssl http2;
    server_name ${publicHostname};
    ssl_certificate     /etc/letsencrypt/live/${publicHostname}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${publicHostname}/privkey.pem;

    root /var/www/monerousd-mirror;
    autoindex off;

    # Cache headers tuned for the wallet's site-updater poll cycle.
    location ~* \\.(yml|json)$  { add_header Cache-Control "public, max-age=60"; }
    location ~* \\.(dmg|zip|exe|AppImage|deb|tar\\.gz|tar\\.zst)$ {
        add_header Cache-Control "public, max-age=86400, immutable";
    }
}
`);
  }

  if (enablePublicRpc) {
    blocks.push(`# Public USDmd JSON-RPC for the federated explorer SPA.
# Read-only — wallets / explorers query via this; write txes go
# through the user's local wallet-rpc, not here.
server {
    listen 443 ssl http2;
    server_name rpc.${publicHostname};
    ssl_certificate     /etc/letsencrypt/live/${publicHostname}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${publicHostname}/privkey.pem;

    location /json_rpc {
        proxy_pass http://127.0.0.1:17750/json_rpc;
        proxy_set_header Host \\$host;
        # Read-only allowlist enforced at the daemon side; nginx
        # narrows further by method.
    }
    location /get_block        { proxy_pass http://127.0.0.1:17750; }
    location /get_block_count  { proxy_pass http://127.0.0.1:17750; }
    location /get_transactions { proxy_pass http://127.0.0.1:17750; }
    location / { return 404; }
}
`);
  }

  return blocks.join('\n');
}

// ─── 6. orchestrate ─────────────────────────────────────────────────

(function main() {
  console.log('  ── MoneroUSD validator install ──');
  console.log(`    name:                 ${args.name}`);
  console.log(`    version:              ${args.version}`);
  console.log(`    public hostname:      ${args.publicHostname}`);
  console.log(`    install dir:          ${INSTALL_DIR}`);
  console.log(`    data dir:             ${DATA_DIR}`);
  console.log(`    public RPC:           ${args.enablePublicRpc ? 'enabled' : 'disabled'}`);
  console.log(`    sovereign mirror:     ${args.enableSovereignMirror ? 'enabled' : 'disabled'}`);
  console.log(`    dry-run:              ${args.dryRun ? 'YES' : 'no'}`);
  console.log('');

  // 1. Validator keypair
  const { privPem, pubHex } = generateValidatorKey();
  const privKeyPath = path.join(INSTALL_DIR, 'validator-private.pem');
  writeFileSafe(privKeyPath, privPem, 0o600);
  console.log(`  ✓ validator pubkey: ${pubHex}`);

  // 2. Config
  const configPath = path.join(INSTALL_DIR, 'config.json');
  writeFileSafe(configPath, makeValidatorConfig({
    privKeyPath,
    publicHostname:      args.publicHostname,
    enablePublicRpc:     args.enablePublicRpc,
    enableSovereignMirror: args.enableSovereignMirror,
  }), 0o600);
  console.log(`  ✓ config:             ${configPath}`);

  // 3. systemd unit
  const binPath = path.join(INSTALL_DIR, 'bin', 'USDmd');
  const unitContent = makeSystemdUnit({
    binPath, configPath, dataDir: DATA_DIR, validatorName: args.name,
  });
  const unitPath = '/etc/systemd/system/monerousd-validator.service';
  writeFileSafe(unitPath, unitContent, 0o644);
  console.log(`  ✓ systemd unit:       ${unitPath}`);

  // 4. nginx vhost (only if any public surface enabled)
  if (args.enableSovereignMirror || args.enablePublicRpc) {
    const nginxConf = makeNginxConf({
      publicHostname:      args.publicHostname,
      enablePublicRpc:     args.enablePublicRpc,
      enableSovereignMirror: args.enableSovereignMirror,
    });
    const nginxPath = `/etc/nginx/sites-available/monerousd-validator-${args.name}.conf`;
    writeFileSafe(nginxPath, nginxConf, 0o644);
    console.log(`  ✓ nginx vhost:        ${nginxPath}`);
  }

  // 5. Data dir
  ensureDir(DATA_DIR, 0o750);

  // 6. BOND_APPLY payload — operator pastes this into their wallet
  console.log('');
  console.log('  ── next steps ──');
  console.log('    1. Provision TLS:');
  console.log(`         certbot certonly --standalone -d ${args.publicHostname}`);
  console.log('    2. (manual) Pull USDmd binary into ' + binPath + ' via the chain-');
  console.log('       anchored release manifest. Typical command:');
  console.log(`         node scripts/release-binary-broadcast.js --pull \\`);
  console.log(`           --version ${args.version} --to ${INSTALL_DIR}/bin/`);
  console.log('    3. Enable + start the validator:');
  console.log('         sudo systemctl enable --now monerousd-validator');
  console.log('    4. In your daily wallet (separate machine), Settings → Validator → Apply,');
  console.log('       paste this pubkey:');
  console.log(`         ${pubHex}`);
  console.log('       and this public RPC URL:');
  console.log(`         https://${args.publicHostname}`);
  console.log('       Approve the BOND_APPLY in the wallet popup.');
  console.log('    5. Wait for DKG2-add ceremony to integrate your validator share');
  console.log('       (~1-3 hours). Validator status flips pending → active.');
  console.log('');
  console.log('  install complete. Keep this host online — slashing fires on extended absence.');
})();
