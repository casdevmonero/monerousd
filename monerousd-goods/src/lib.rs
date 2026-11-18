// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The goods and services layer's off-chain core.
//!
//! Spec: `docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md`.
//!
//! - [`offer`]: the one merchant-signed object behind every checkout (a point-of-sale charge, a protected
//!   purchase, a subscription). One encoding, one parser.
//! - [`rules`]: what a protected purchase pays, to whom, on each event. Integer arithmetic, and every path
//!   pays out exactly what was locked.
//! - [`notice`]: the check of a carrier's own signed delivery notice, and the single fact read from it.
//! - [`checkout`]: one shipped order from the offer to the last payout, and what the checkout helper tells the shop.
//!
//! Nothing here touches the chain, a node or a network. A normal payment between two people uses none of it.

pub mod checkout;
pub mod notice;
pub mod offer;
pub mod rules;
