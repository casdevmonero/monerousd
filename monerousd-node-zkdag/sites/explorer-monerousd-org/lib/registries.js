// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// registries.js — the few things the explorer knows without asking the chain: the chain's two native assets and the
// organizations that build it. Everything else (tokens, NFTs, collections, @names, pools) is read from the chain by
// lib/chain.js. Nothing here stands in for chain data. The bridge swaps the native coins themselves (BTC, XMR, ETH,
// ZEC, SOL) to and from USDm.

export const NATIVE_ASSETS = Object.freeze([
  {
    symbol: 'USDm',
    name: 'MoneroUSD',
    kind: 'native',
    logoUrl: 'assets/coins/USDm.svg',
    org: 'monerousd-protocol',
    description: 'The chain’s private dollar. Amounts, senders and receivers are hidden in every payment.',
  },
  {
    symbol: 'SAT',
    name: 'Satoshi',
    kind: 'native',
    logoUrl: 'assets/logos/sat.png',
    org: 'monerousd-protocol',
    description: 'The chain’s reward asset: 21 million at most, issued as block rewards; validators bond it.',
  },
]);

// The verified symbols: a token another creator names "USDm" or "SAT" is shown with a warning, never the check.
export const VERIFIED_TOKENS = NATIVE_ASSETS;

export const BRIDGE_COINS = Object.freeze([
  { symbol: 'BTC', name: 'Bitcoin', logoUrl: 'assets/coins/BTC.svg' },
  { symbol: 'XMR', name: 'Monero',  logoUrl: 'assets/coins/XMR.svg' },
  { symbol: 'ETH', name: 'Ether',   logoUrl: 'assets/coins/ETH.svg' },
  { symbol: 'ZEC', name: 'Zcash',   logoUrl: 'assets/coins/ZEC.svg' },
  { symbol: 'SOL', name: 'Solana',  logoUrl: 'assets/coins/SOL.svg' },
]);

export const VERIFIED_ORGS = Object.freeze([
  {
    slug: 'monerousd-protocol',
    name: 'MoneroUSD Protocol',
    blurb: 'The chain, the wallet, Letter, the Veil, Sovereign hosting and the USDm dollar.',
    website: 'https://monerousd.org',
    badges: ['core'],
    logoUrl: 'assets/logos/monerousd.svg',
  },
  {
    slug: 'ion-swap',
    name: 'IonSwap',
    blurb: 'Private swaps and pools on MoneroUSD: native BTC, XMR, ETH, ZEC and SOL to USDm, token launches and the NFT marketplace.',
    website: 'https://ion.monerousd.org',
    badges: ['dex', 'bridge'],
    logoUrl: 'assets/logos/ion-swap.svg',
  },
]);

export function getOrg(slug) {
  return VERIFIED_ORGS.find(o => o.slug === slug) || null;
}

export function logoUrlFor(entry) {
  if (entry && entry.logoUrl) return entry.logoUrl;
  const native = NATIVE_ASSETS.find(a => a.symbol === (entry && entry.symbol));
  return native ? native.logoUrl : '';
}

export function initials(name) {
  if (!name) return '?';
  return String(name).split(/[\s\-_/]+/).filter(Boolean).slice(0, 2).map(s => s[0].toUpperCase()).join('') || '?';
}
