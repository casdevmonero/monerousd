// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE ONE TABLE OF BRIDGE COINS (user 2026-11-10: the bridge widens from Bitcoin and Monero to more coins, and
//! "if the btc and xmr bridge get stronger and more secure, so do those as well automatically").
//!
//! WHAT WAS WRONG. Which coins the bridge holds was written down in many places, each as a two-way choice: `peg::ASSETS`,
//! `BRIDGE_LEDGERS`, `COIN_LEDGERS`, `defi_batch::pair_y_tag` (`if pair == 0 { Bitcoin } else { Monero }`),
//! `peg_pool::coin_denoms`, the price route's ticker lookup, the wallet's `match asset { "BTC" => 1e8, "XMR" => 1e12 }`
//! and the app's own list. A third coin added at one of them and not the others is a coin the chain half knows: the class
//! this project has met four times as "fixed one of N" (§9.5).
//!
//! THE SHAPE. One row per coin, here. A row states the facts every door needs and nothing a door decides: the ticker and
//! name people read, how many atoms make one coin, what an observer of the coin's own chain can see, and the ledgers and
//! pool pair the chain already gives it. Every reader asks this table. A coin is offered by adding its row once its vault,
//! watcher and payout lane exist on real nodes; a row never stands for a coin the bridge cannot yet hold (testnet equals
//! production: nothing is listed that does not work).
//!
//! WHAT A ROW DOES NOT CARRY: a price (the chain's price mark, `price_mark_tx`), a balance or a count (DIGITAL CASH: the
//! reserve's amounts are committed, never served), or any key (custody keys are each custodian's own, `btc_payout`,
//! `xmr_custody`).
//!
//! BORROWED: THORChain's chain and pool registry (one entry per external asset, every module reads the same entry).
//! ROOT-LAYER: constants only; this module moves no value and admits no outside bytes (it is not a door, §9.6).
//! Cons, quantified: none at rest and none on the wire (a `&'static` table of two rows today, 0 bytes in any block).

/// What an observer of the coin's OWN chain can see of a deposit or a payout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainView {
    /// Amounts, addresses and times are all visible (Bitcoin).
    Public,
    /// Amounts and owners are hidden by the coin's own chain (Monero).
    Shielded,
}

impl ChainView {
    /// The word the wallet and the apps show for it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            ChainView::Public => "public",
            ChainView::Shielded => "shielded",
        }
    }
}

/// ⭐ WHAT AUTO-OPSEC DOES WITH A DEPOSIT OF THIS COIN. Auto-OPSEC is the wallet's ONE privacy setting, on by default
/// (user 2026-10-28), and it is on by default for every coin this table will ever hold (user 2026-11-12, verbatim: "make
/// sure auto opsec is on by default for the new native assets as well (eth, sol, zec etc)"). What the setting does for a
/// deposit depends on what the coin's own chain shows, so every row names its defence here. There is no arm for
/// "nothing": a coin cannot enter the table without one, and every flow that acts on a deposit matches on this field,
/// never on a ticker (MEASURED 2026-11-12, lane goods: the swap's entry-mix branch read `from == "BTC"`, so a new public
/// coin added through this table would have minted with no deposit defence at all). A coin whose chain needs a defence
/// not listed adds its arm, and each `match` on it stops compiling until that flow implements it. The payout side is the
/// shared lane's for every row (standard rungs, each in its own batch among other people's, to fresh addresses), and a
/// row is added only when `swap_linkability` holds for it (spec `docs/BRIDGE-MORE-COINS-SPEC-20261110.md` §4).
/// AI RESISTANT: (b) ordinary code; the claim it protects is measured by the linkability census, not declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositOpsec {
    /// The coin's own chain shows the deposit (amount, address, time): it is co-signed into the entry mix before it
    /// mints, so what leaves the mix cannot be told from anyone else's (Bitcoin: the wallet's `coin_swap_mix_start`).
    EntryMix,
    /// The coin's own chain hides amounts and owners, and the deposit goes to a one-time address of the vault: there is
    /// nothing on that chain for a mix to hide (Monero).
    OwnChainShielded,
}

/// One coin the bridge holds on its own chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeCoin {
    /// The ticker people read ("BTC").
    pub ticker: &'static str,
    /// The coin's name ("Bitcoin").
    pub name: &'static str,
    /// Atoms per coin, as a power of ten: Bitcoin 8 (satoshis), Monero 12 (piconero).
    pub decimals: u32,
    /// What its own chain shows an observer.
    pub view: ChainView,
    /// Its stablecoin ledger (`peg::NATIVE_PEG_ASSET_ID`, `peg::XMR_PEG_ASSET_ID`): the reserve MoneroUSD is minted
    /// against, valued by the coin's price mark. This is also the id its price mark carries.
    pub psm_ledger: u32,
    /// Its coin ledger (`peg::COIN_LEDGERS`): one atom on the chain per atom in custody, no price read.
    pub coin_ledger: u32,
    /// Its SAT pool's pair (`defi_batch::PAIRS`).
    pub pair: u8,
    /// What auto-OPSEC (on by default) does with a deposit of it ([`DepositOpsec`]).
    pub deposit_opsec: DepositOpsec,
}

/// ⭐ THE TABLE, in ledger order. Bitcoin and Monero are the coins whose vault, watcher and payout lane run on real nodes
/// today (`btc_payout`, `xmr_custody`, `xmr_payout`).
pub const COINS: &[BridgeCoin] = &[
    BridgeCoin {
        ticker: "BTC",
        name: "Bitcoin",
        decimals: 8,
        view: ChainView::Public,
        psm_ledger: crate::peg::NATIVE_PEG_ASSET_ID,
        coin_ledger: crate::peg::COIN_BTC_ASSET_ID,
        pair: 0,
        deposit_opsec: DepositOpsec::EntryMix,
    },
    BridgeCoin {
        ticker: "XMR",
        name: "Monero",
        decimals: 12,
        view: ChainView::Shielded,
        psm_ledger: crate::peg::XMR_PEG_ASSET_ID,
        coin_ledger: crate::peg::COIN_XMR_ASSET_ID,
        pair: 1,
        deposit_opsec: DepositOpsec::OwnChainShielded,
    },
];

/// The coin with this ticker (exact, upper case).
#[must_use]
pub fn by_ticker(ticker: &str) -> Option<&'static BridgeCoin> {
    COINS.iter().find(|c| c.ticker == ticker)
}

/// The coin whose stablecoin ledger (and price mark) carries this id.
#[must_use]
pub fn by_psm_ledger(asset_id: u32) -> Option<&'static BridgeCoin> {
    COINS.iter().find(|c| c.psm_ledger == asset_id)
}

/// The coin whose coin ledger carries this id.
#[must_use]
pub fn by_coin_ledger(asset_id: u32) -> Option<&'static BridgeCoin> {
    COINS.iter().find(|c| c.coin_ledger == asset_id)
}

/// The coin a SAT pool's pair trades.
#[must_use]
pub fn by_pair(pair: u8) -> Option<&'static BridgeCoin> {
    COINS.iter().find(|c| c.pair == pair)
}

impl BridgeCoin {
    /// Atoms in one coin.
    #[must_use]
    pub const fn atoms_per_coin(&self) -> u128 {
        10u128.pow(self.decimals)
    }

    /// ⭐ A PRICE MARK IN MILLIONTHS OF A DOLLAR PER COIN, exact integer arithmetic. A mark is MoneroUSD atoms per coin atom
    /// times `liquidation::PRICE_SCALE`; one coin is `10^decimals` atoms and one dollar is `USDM_ATOMIC_PER_DOLLAR`
    /// MoneroUSD atoms, so dollars per coin = `mark × 10^decimals / (PRICE_SCALE × USDM_ATOMIC_PER_DOLLAR)`. Returned in
    /// millionths so no float is formed on the node; `None` only if the product leaves `u128` (a mark above 3.4e26, which
    /// no door admits).
    #[must_use]
    pub fn micro_dollars_per_coin(&self, mark: u128) -> Option<u128> {
        let per_dollar = u128::from(crate::peg_pool::USDM_ATOMIC_PER_DOLLAR);
        mark.checked_mul(self.atoms_per_coin())?.checked_mul(1_000_000)?.checked_div(crate::liquidation::PRICE_SCALE.checked_mul(per_dollar)?)
    }
}

/// Millionths of a dollar as a decimal string with six places ("74282.306163"): the wire form of a price a page shows.
#[must_use]
pub fn micro_to_decimal(micro: u128) -> String {
    format!("{}.{:06}", micro / 1_000_000, micro % 1_000_000)
}

#[cfg(test)]
mod bridge_assets_tests {
    use super::*;

    /// The table and the constants the doors were written against say the same thing, in the same order: a row added or
    /// moved without its ledgers is refused here, before any node disagrees with another.
    #[test]
    fn the_table_matches_every_ledger_the_doors_already_use() {
        assert_eq!(COINS.len(), crate::peg::ASSETS.len());
        for (i, c) in COINS.iter().enumerate() {
            assert_eq!(c.ticker, crate::peg::ASSETS[i], "the price route names a mark by its ledger's place in `peg::ASSETS`");
            assert_eq!(c.psm_ledger, crate::peg::BRIDGE_LEDGERS[i]);
            assert_eq!(c.coin_ledger, crate::peg::COIN_LEDGERS[i]);
            assert_eq!(usize::from(c.pair), i);
            assert_eq!(crate::defi_batch::pair_y_tag(c.pair), usdm_decider::whir_rec_block::wrapped_asset_tag_u32(c.coin_ledger));
        }
        assert_eq!(usize::from(crate::defi_batch::PAIRS), COINS.len());
        assert_eq!(by_psm_ledger(crate::price_relay::XMR_ASSET_ID).map(|c| c.ticker), Some("XMR"));
    }

    /// No two rows share a ticker, a ledger or a pair, and no ledger id is both a stablecoin ledger and a coin ledger.
    #[test]
    fn no_two_coins_share_a_name_a_ledger_or_a_pool() {
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        let mut pairs = std::collections::BTreeSet::new();
        for c in COINS {
            assert!(names.insert(c.ticker), "{} twice", c.ticker);
            assert!(ids.insert(c.psm_ledger) && ids.insert(c.coin_ledger), "{} reuses a ledger id", c.ticker);
            assert!(pairs.insert(c.pair), "{} reuses a pool pair", c.ticker);
        }
    }

    /// The dollar figure of a mark, against numbers real nodes stood on (2026-11-10, both nodes, relays nobody typed):
    /// Bitcoin's mark 74,282,306,163 is $74,282.306163 a coin and Monero's 56,079 is $560.79 a coin. A wrong decimal count
    /// is off by a factor of ten thousand, and a wallet that showed it would quote a deposit at the wrong amount.
    #[test]
    fn a_mark_reads_as_the_dollars_real_nodes_stood_on() {
        let btc = by_ticker("BTC").unwrap();
        let xmr = by_ticker("XMR").unwrap();
        assert_eq!(btc.micro_dollars_per_coin(74_282_306_163).map(micro_to_decimal).as_deref(), Some("74282.306163"));
        assert_eq!(xmr.micro_dollars_per_coin(56_079).map(micro_to_decimal).as_deref(), Some("560.790000"));
        assert_eq!(btc.micro_dollars_per_coin(u128::MAX), None, "an overflowing mark has no dollar figure, never a wrapped one");
        assert_eq!(micro_to_decimal(1), "0.000001");
        assert!(by_ticker("btc").is_none() && by_ticker("ETH").is_none(), "a coin with no vault on real nodes has no row");
    }

    /// ⛔ AUTO-OPSEC ON EVERY COIN (user 2026-11-12) — a coin whose own chain SHOWS its deposits is never given the defence
    /// of a chain that hides them: every public-chain row is mixed before it mints. (A row with no defence cannot be
    /// written at all: [`DepositOpsec`] has no such arm.)
    #[test]
    fn every_public_chain_coin_is_mixed_before_it_mints() {
        for c in COINS {
            match (c.view, c.deposit_opsec) {
                (ChainView::Public, DepositOpsec::EntryMix) | (ChainView::Shielded, DepositOpsec::OwnChainShielded | DepositOpsec::EntryMix) => {}
                (ChainView::Public, DepositOpsec::OwnChainShielded) => {
                    panic!("⛔ {} shows its deposits on its own chain and was given the defence of a shielded chain: auto-OPSEC would do nothing for it", c.ticker)
                }
            }
        }
        assert_eq!(by_ticker("BTC").map(|c| c.deposit_opsec), Some(DepositOpsec::EntryMix), "CALIBRATION: Bitcoin is the public chain the entry mix exists for");
    }
}
