#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/**
 * publish-sovereign-site.js — release-pipeline CLI for the Sovereign Web
 * Hosting protocol. Builds a deterministic gzipped USTAR bundle from a
 * folder, computes its SHA-256 rootHash, optionally pre-stages it on an
 * Ion Swap indexer, and emits a manifest the operator pastes into the
 * desktop wallet's Publish wizard (or feeds to a custom signer).
 *
 * It does NOT broadcast SITE_PUBLISH on its own — broadcast happens
 * through the wallet's walletBroadcast() pipeline so the carrier tx,
 * approval modal, and reserve-routed fee all flow through the same
 * code path the dashboard uses (rule 1, SW-11, SW-12, SW-17).
 *
 * Usage:
 *   node scripts/publish-sovereign-site.js \
 *       --src     ./out/monerousd-org \
 *       --domain  monerousd.org \
 *       --version 1.2.166 \
 *       --content static \
 *       [--upload https://ion.monerousd.org] \
 *       [--out    ./build-1261/sites/monerousd-org/_meta.json] \
 *       [--write-bundle ./dist/monerousd-org-1.2.166.tar.gz]
 *
 * Exit codes:
 *    0   success — manifest printed, optional upload OK
 *    1   bundle build / hash failure
 *    2   indexer upload failure
 *    3   bad args
 *
 * The output JSON manifest is the exact shape `provider.publishSite()`
 * accepts, so a curl-driven release script can pipe this into a wallet
 * RPC if/when one is exposed.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// ---------------- args -----------------------------------------------

function parseArgs(argv) {
  const out = { content: 'static' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--src')         out.src = argv[++i];
    else if (a === '--domain') out.domain = argv[++i];
    else if (a === '--version')out.version = argv[++i];
    else if (a === '--content')out.content = argv[++i];
    else if (a === '--upload') out.upload = argv[++i];
    else if (a === '--out')    out.out = argv[++i];
    else if (a === '--write-bundle') out.writeBundle = argv[++i];
    else if (a === '--quiet')  out.quiet = true;
    else if (a === '-h' || a === '--help') out.help = true;
  }
  return out;
}

function usageAndExit(code) {
  console.error(
    'Usage: publish-sovereign-site --src <dir> --domain <name> --version <semver>\n' +
    '         [--content static|spa|spa-with-api] [--upload <indexer>]\n' +
    '         [--out <_meta.json>] [--write-bundle <file>] [--quiet]'
  );
  process.exit(code);
}

const args = parseArgs(process.argv);
if (args.help) usageAndExit(0);
if (!args.src || !args.domain || !args.version) usageAndExit(3);
if (!['static', 'spa', 'spa-with-api'].includes(args.content)) {
  console.error('--content must be one of: static, spa, spa-with-api');
  usageAndExit(3);
}

const srcAbs = path.resolve(args.src);
if (!fs.existsSync(srcAbs) || !fs.statSync(srcAbs).isDirectory()) {
  console.error('source path not a directory: ' + srcAbs);
  process.exit(3);
}

// ---------------- deterministic bundle build -------------------------
// Mirrors build-1261/main.js _writeTarHeader + sovereign:pack-bundle.
// Zeroes mtime/uid/gid/uname/gname so the tarball is byte-stable across
// machines and identical inputs always hash to identical rootHashes.

const MAX_BUNDLE_BYTES = 2 * 1024 * 1024;

function walk(rootDir, baseDir, out) {
  const ents = fs.readdirSync(rootDir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0
  );
  for (const ent of ents) {
    if (ent.name === '_meta.json') continue; // never include — we emit it ourselves
    if (ent.name.startsWith('.')) continue;  // skip dotfiles by default
    const full = path.join(rootDir, ent.name);
    const rel = path.relative(baseDir, full).split(path.sep).join('/');
    if (ent.isDirectory()) walk(full, baseDir, out);
    else if (ent.isFile()) out.push({ rel, abs: full });
  }
}

function writeTarHeader(name, size, mode) {
  const buf = Buffer.alloc(512);
  let prefix = '';
  let n = name;
  if (n.length > 100) {
    const slash = n.lastIndexOf('/', 100);
    if (slash > 0 && (n.length - slash - 1) <= 100) {
      prefix = n.slice(0, slash);
      n = n.slice(slash + 1);
    } else {
      throw new Error('path too long for USTAR: ' + name);
    }
  }
  buf.write(n, 0, 100, 'utf8');
  buf.write((mode & 0o7777).toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
  buf.write('0000000\0', 108, 8, 'ascii'); // uid
  buf.write('0000000\0', 116, 8, 'ascii'); // gid
  buf.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  buf.write('00000000000\0', 136, 12, 'ascii'); // mtime = 0
  for (let i = 148; i < 156; i++) buf[i] = 0x20; // chksum placeholder
  buf[156] = '0'.charCodeAt(0); // typeflag
  buf.write('ustar\0', 257, 6, 'ascii');
  buf.write('00', 263, 2, 'ascii');
  // uname / gname zeroed
  if (prefix) buf.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += buf[i];
  buf.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return buf;
}

function buildBundle(srcDir) {
  const files = [];
  walk(srcDir, srcDir, files);
  files.sort((a, b) => a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0);

  let uncompressedSize = 0;
  const blocks = [];
  for (const f of files) {
    const data = fs.readFileSync(f.abs);
    blocks.push(writeTarHeader(f.rel, data.length, 0o644));
    blocks.push(data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad > 0) blocks.push(Buffer.alloc(pad));
    uncompressedSize += data.length;
  }
  // Two zero blocks → end of archive.
  blocks.push(Buffer.alloc(512));
  blocks.push(Buffer.alloc(512));

  const tar = Buffer.concat(blocks);
  const gz = zlib.gzipSync(tar, { level: 9 });
  if (gz.length > MAX_BUNDLE_BYTES) {
    throw new Error('bundle exceeds max ' + MAX_BUNDLE_BYTES + ' bytes (got ' + gz.length + ')');
  }
  const rootHash = crypto.createHash('sha256').update(gz).digest('hex');
  return { gz, rootHash, fileCount: files.length, uncompressedSize };
}

// ---------------- fee preview ----------------------------------------
//
// The CLI doesn't have access to the wallet's site-fee-curve module
// (which lives inside the desktop wallet bundle), but we mirror the
// curve here so release engineers see the expected fee before they
// open the wallet.

const ATOMIC = 100_000_000n;
const BOND_FLOOR_LONG = 25n * ATOMIC;
const BOND_MID        = 100n * ATOMIC;
const BOND_SHORT      = 500n * ATOMIC;
const BOND_PREMIUM    = 5000n * ATOMIC;
const UPDATE_BASE     = 1n * ATOMIC;
const UPDATE_PER_KB   = ATOMIC / 100n; // 0.01 USDm/KB

function bareName(domain) {
  const d = String(domain || '').toLowerCase();
  if (d.endsWith('.dark-sites.local')) return d.slice(0, -('.dark-sites.local'.length));
  return d.replace(/\..+$/, '');
}

function bondForDomain(domain) {
  const len = bareName(domain).length;
  if (len <= 3) return BOND_PREMIUM;
  if (len <= 6) return BOND_SHORT;
  if (len <= 10) return BOND_MID;
  return BOND_FLOOR_LONG;
}

function updateFee(bundleSize) {
  const kb = BigInt(Math.ceil((bundleSize || 0) / 1024));
  return UPDATE_BASE + kb * UPDATE_PER_KB;
}

function fmtUSDm(atomic) {
  const a = BigInt(atomic);
  const whole = a / ATOMIC;
  const frac  = a - whole * ATOMIC;
  const fracStr = frac.toString().padStart(8, '0').replace(/0+$/, '');
  return fracStr ? whole.toString() + '.' + fracStr : whole.toString();
}

// ---------------- main -----------------------------------------------

(async () => {
  let bundle;
  try {
    bundle = buildBundle(srcAbs);
  } catch (e) {
    console.error('bundle build failed: ' + (e && e.message || e));
    process.exit(1);
  }

  const bondAtomic   = bondForDomain(args.domain);
  const updateAtomic = updateFee(bundle.gz.length);
  const firstFee     = bondAtomic + updateAtomic;
  const updateOnly   = updateAtomic;

  const manifest = {
    domain: String(args.domain).toLowerCase(),
    version: String(args.version),
    contentType: args.content,
    rootHash: bundle.rootHash,
    bundleSize: bundle.gz.length,
    bundleBase64: bundle.gz.toString('base64'),
    fileCount: bundle.fileCount,
    uncompressedSize: bundle.uncompressedSize,
    fees: {
      ifFirstPublish: { atomic: firstFee.toString(),  formatted: fmtUSDm(firstFee)  + ' USDm' },
      ifUpdate:       { atomic: updateOnly.toString(), formatted: fmtUSDm(updateOnly) + ' USDm' },
      bond:           { atomic: bondAtomic.toString(), formatted: fmtUSDm(bondAtomic) + ' USDm' },
      update:         { atomic: updateAtomic.toString(), formatted: fmtUSDm(updateAtomic) + ' USDm' },
      reserveContribution: '100% routes to protocol reserve',
    },
    note: 'Paste this manifest into the wallet\'s Sovereign Hosting → Publish wizard, ' +
          'or POST .bundleBase64 to the wallet\'s sovereignPublishSite IPC bridge.',
  };

  // Optional: write _meta.json next to the source for the wallet's T1 ship path.
  if (args.out) {
    const outPath = path.resolve(args.out);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    const t1Meta = {
      domain: manifest.domain,
      version: manifest.version,
      rootHash: manifest.rootHash,
      bundleSize: manifest.bundleSize,
      contentType: manifest.contentType,
      fileCount: manifest.fileCount,
      tier: 'T1',
      shippedAt: new Date().toISOString(),
    };
    fs.writeFileSync(outPath, JSON.stringify(t1Meta, null, 2) + '\n', 'utf8');
    if (!args.quiet) console.error('  wrote ' + outPath);
  }

  // Optional: dump the binary bundle to disk for offline distribution / signing.
  if (args.writeBundle) {
    const bp = path.resolve(args.writeBundle);
    fs.mkdirSync(path.dirname(bp), { recursive: true });
    fs.writeFileSync(bp, bundle.gz);
    if (!args.quiet) console.error('  wrote ' + bp);
  }

  // Optional: pre-stage the bundle on an indexer so /v1/sites/:domain/bundle
  // resolves immediately after SITE_PUBLISH lands. Backend hash-verifies on
  // ingest (SW-1 at the registry edge), so a wrong/tampered bundle is
  // rejected here before any chain action.
  if (args.upload) {
    const url = String(args.upload).replace(/\/+$/, '') +
      '/api/sites/' + encodeURIComponent(manifest.domain) + '/bundle';
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => { try { ctrl.abort(); } catch (_) {} }, 90_000);
      const r = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Sovereign-Domain':    manifest.domain,
          'X-Sovereign-Version':   manifest.version,
          'X-Sovereign-Roothash':  manifest.rootHash,
        },
        body: bundle.gz,
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!r.ok) {
        const txt = await r.text().catch(() => '');
        console.error('upload failed: HTTP ' + r.status + ' ' + txt);
        process.exit(2);
      }
      if (!args.quiet) console.error('  uploaded → ' + url);
    } catch (e) {
      console.error('upload error: ' + (e && e.message || e));
      process.exit(2);
    }
  }

  // Manifest goes to stdout so it can be piped to a wallet RPC or a signer.
  // Strip bundleBase64 unless a flag explicitly requests it — the binary
  // bytes blow up CI logs.
  const printable = { ...manifest };
  if (!process.env.PUBLISH_INCLUDE_BUNDLE_B64) delete printable.bundleBase64;
  process.stdout.write(JSON.stringify(printable, null, 2) + '\n');
})();
