#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────
// generate-bnb-signing-key.js — fresh BNB Chain hot-wallet key.
//
// Generates a secp256k1 keypair (same crypto as Ethereum), derives
// the EVM address, prints both to the terminal ONCE, and writes the
// private key to a 0600-permission file. Nothing persists in this
// process beyond that file.
//
// Usage:
//   node scripts/generate-bnb-signing-key.js
//
// Output:
//   ~/.bridge-bnb-signing-key   (0600, hex-encoded private key)
//   stdout: address + matching env line for /etc/ion/backend.env
//
// AFTER RUNNING:
//   1. Save the private key offline (paper / 1Password / Vault).
//   2. scp ~/.bridge-bnb-signing-key root@$MONEROUSD_VPS_HOST:/etc/ion/
//   3. Append the env line to /etc/ion/backend.env on the VPS.
//   4. systemctl restart ion-backend.service
//   5. Fund the BNB Chain address with enough BNB for gas + reserves.
//
// SECURITY WARNING:
//   This script runs in a normal terminal. The key bytes are visible
//   on screen for a few seconds. Don't run it in a screen-shared
//   session, on a public machine, or anywhere keystrokes are logged.
// ─────────────────────────────────────────────────────────────────

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

function bytesToHex(b) {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

// ── Generate a fresh keypair ────────────────────────────────────

const privKey = secp256k1.utils.randomPrivateKey();   // 32 bytes
const pubKey = secp256k1.getPublicKey(privKey, false); // uncompressed, 65 bytes (0x04 || X || Y)
const addrHash = keccak_256(pubKey.slice(1));          // skip 0x04 prefix
const evmAddr = '0x' + bytesToHex(addrHash.slice(-20));

// EIP-55 checksum (mixed-case for typo resistance).
function eip55Checksum(addr) {
  const lower = addr.toLowerCase().replace('0x', '');
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lower)));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}
const checksumAddr = eip55Checksum(evmAddr);
const privKeyHex = bytesToHex(privKey);

// ── Write the private-key file (0600) ───────────────────────────

const HOME = os.homedir();
const KEY_FILE = path.join(HOME, '.bridge-bnb-signing-key');

if (fs.existsSync(KEY_FILE)) {
  console.error(`✗ ${KEY_FILE} already exists. Delete it first if you're SURE you want to overwrite.`);
  process.exit(1);
}
fs.writeFileSync(KEY_FILE, privKeyHex + '\n', { mode: 0o600 });
fs.chmodSync(KEY_FILE, 0o600);

// ── Output ──────────────────────────────────────────────────────

console.log('');
console.log('═'.repeat(63));
console.log('  BNB Chain hot-wallet signing key generated.');
console.log('═'.repeat(63));
console.log('');
console.log('  Address (EIP-55 checksum):');
console.log(`    ${checksumAddr}`);
console.log('');
console.log('  Private key (HEX) — saved to:');
console.log(`    ${KEY_FILE}      (mode 0600, owner-only)`);
console.log('');
console.log('  Private key (HEX) — INLINE (back this up offline NOW,');
console.log('  then clear your terminal scrollback):');
console.log(`    ${privKeyHex}`);
console.log('');
console.log('═'.repeat(63));
console.log('  Next steps');
console.log('═'.repeat(63));
console.log('');
console.log('  1. Back up the key offline. Suggested: 1Password / Vault /');
console.log('     paper. The file at ~/.bridge-bnb-signing-key is');
console.log('     0600 owner-only, NOT a backup.');
console.log('');
console.log('  2. Copy the key file to the VPS:');
console.log('       scp ~/.bridge-bnb-signing-key root@$MONEROUSD_VPS_HOST:/etc/ion/');
console.log('       ssh root@$MONEROUSD_VPS_HOST \'chmod 600 /etc/ion/.bridge-bnb-signing-key\'');
console.log('');
console.log('  3. Append to /etc/ion/backend.env on the VPS:');
console.log('       BRIDGE_BNB_SIGNING_KEY_FILE=/etc/ion/.bridge-bnb-signing-key');
console.log('       BRIDGE_BNB_RESERVE_ADDR=' + checksumAddr);
console.log('');
console.log('  4. systemctl restart ion-backend.service on the VPS.');
console.log('');
console.log('  5. Fund the BNB Chain address with enough BNB for:');
console.log('       - gas (~0.01 BNB minimum)');
console.log('       - reserves (whatever wBNB circulating supply you expect)');
console.log('     Send funds to:');
console.log(`       ${checksumAddr}`);
console.log('     on chain id 56 (BNB Smart Chain mainnet).');
console.log('');
console.log('  6. Verify by tailing journalctl after restart — the');
console.log('     line "[address-gen] No keys loaded for BNB" should');
console.log('     no longer appear.');
console.log('');
console.log('═'.repeat(63));
console.log('  CLEAR YOUR TERMINAL NOW: Ctrl+L (or `clear`)');
console.log('═'.repeat(63));
