// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22 6 — MONERO DAEMONS CROSS-CHECKED (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §22 6).
//!
//! A custodian's Monero wallet sees the reserve's incoming deposits through ONE daemon. A lying or eclipsed daemon could show
//! a deposit that is not on Monero's chain, or deeper than it is. So no deposit counts until ≥ 3 independent Monero daemons,
//! reached as onion services, report the same block height for its transaction (`btc_filter::agree` — one daemon answering
//! twice is one, any second height is a conflict that no majority settles), and its depth is read from the LOWEST tip among
//! those three (a daemon overstating its tip cannot hurry a deposit).
//!
//! The daemon set: the release's onion list on mainnet; `MONEROUSD_XMR_DAEMON_ONIONS` (comma-separated `http://….onion:port`)
//! on a test network. Fewer than three: no deposit matures (fail closed), and the log says why. In the simulator, its one
//! chain answers as three honest daemons.
//!
//! cons: two small onion requests per daemon per unmatured deposit per sweep (each deposit's verdict is kept once matured,
//! dropped with its swap).
//!
//! CLASSICAL-BRIDGE-ENDPOINT: a foreign chain's public data, read-only. DIGITAL-CASH-PRIVACY-REVIEWED: the request names one
//! transaction id to a daemon over onion — the same id the custody wallet's own daemon already serves; no address, no amount.

use crate::btc_filter::{agree, Agreement};

/// Monero mainnet daemons reached as onion services (Tor v3), from monero.fail's public list (read 2026-10-30): the
/// cross-check set. Any three that agree count; none is trusted alone.
pub const MAINNET_DAEMONS: &[&str] = &[
    "http://moneroexnovtlp4datcwbgjznnulgm7q34wcl6r4gcvccruhkceb2xyd.onion:18089",
    "http://monerof5eqykw3hfrjmb66v7r4ft4hlilfzjw5q4huwolttutjuc5dyd.onion:18089",
    "http://monero3x5yrb7tsalxx64tr2qhfw54xy3eudhswvpaskfvsdk2tzb3id.onion:18089",
    "http://plowsoffjexmxalw73tkjmf422gq6575fc7vicuu4javzn2ynnte6tyd.onion:18089",
    "http://ulmlrardljg3r6urejlm6c2tikp3krvkupmdnueahmj33vl5ztez7jqd.onion:18081",
    "http://ncbkcouzbqzcskr3dy26bvgzztpt7ywtjd2ly2bpv5c5zfxoht7gthad.onion:18081",
    "http://mexymskdcpunttj3kozziuw62aryumjggulew2kafk7rmvkmegrrgfyd.onion:18081",
    "http://libertytmtitynvmnto2k42liys5fenb3wabaozmmmksyrc7jvgmjiqd.onion:18089",
    "http://6jvn5tinwxnp723vnsvekroaniq7qkag7nkdqmcwlbinxnpeonaowayd.onion:18089",
    "http://plowsofe6cleftfmk2raiw5h2x66atrik3nja4bfd3zrfa2hdlgworad.onion:18089",
    "http://i4jsfwmw22yjzzmzkoc7aahiaqlyhnykn5wxel43u3o5ibz2k4275jqd.onion:18081",
    "http://6dsdenp6vjkvqzy4wzsnzn6wixkdzihx3khiumyzieauxuxslmcaeiad.onion:18081",
    "http://xmrrpcmyrz3imrldcwiqt4vm5asq2vefgzybamxdigx37p3ctfcjnsad.onion:18089",
    "http://un4yrhwq4d53caoiaadeiur5e5wgkgp74zw3p3twqh3nxh6ztz347dad.onion:18081",
    "http://twiy7ceov5gskxlsqfsmlubbivse5duo3ro7xmrimrgfp3whwfmzi4id.onion:18081",
    "http://doggettffpqokvkukhwquchg6bxwwtgj4pckygqylc7qkhim3ruxncid.onion:18089",
    "http://uthbgw7px3nal7cxtesev2eapqtilaq5vevdjzzqdlxyd2jefk2ogryd.onion:18081",
    "http://duefzsrvotikkballbidlz3hyv7qanghnzwxbmvv6zn5vzux4ashisqd.onion:18089",
    "http://h43iimyfp6n5uzefryl6vhs5nzng6o3pjpukcwoxulahsfb23yledyqd.onion:18081",
    "http://irsdotgovszfg73zsmi5nqguhn66sysmas7u7iwftmcuaw6so2erwdqd.onion:18089",
    "http://6ojekl3uqinseoiigf3zgfj7hvxvjld76fguygpn7u74cxbkvegtidid.onion:18089",
    "http://doggett7s4q4tilfcmonxtj6jz3rzqkwwmu6xwlb7jrtszojm4kpkdid.onion:18089",
    "http://zxwfef533nw5fe7ya5bzkq3iibmudu7ea6qjpqobp3zhucwbpalqi5ad.onion:18089",
    "http://sanlorenzo6i7f27e4wumys2q7wfikgowisxg6pnc2vet7k3wqvyfoqd.onion:18089",
    "http://xmrxmrxmrjau5dcdxzqrqicpai57njom6h5sd4qjitekkemfk6weppyd.onion:18081",
    "http://doggettavnnnctrwm5dv6k42zmtl5f7j2n7sadfmibmnel4cantlf2id.onion:18089",
    "http://xmrnodei64luhuwm4qfi7jga2k3tdpy7l2ovbledihfjgt2xvvw3paad.onion:18089",
    "http://5t4hp2ea6yi7v4yoexkansebpqvz2nwxw25rcsy6rlsr5rckn43h2aqd.onion:18081",
    "http://csxmritzk2qdgqmou2vwyrwu65xabimvmeniestaartks4fhlocfoeyd.onion:18081",
    "http://doggettmvrazr2i5yrkcszhkdrjyooi6efuaf37zcmg7uqqprrg7ymqd.onion:18089",
    "http://ytxu76rr3cn5ui2jdqjlpvxtaegebrnxyc3o6axvyrp2vkibpqn6agyd.onion:18081",
    "http://qcnfaqsyl3uhi5plwnng2ycbq4lokc2vpwdnztkd3sp5rpnplgoegoad.onion:18081",
    "http://yjfevt2jz2bqbvlgxzq7aggb5nftalxwyeupg64ttnu5qh4yqbug2cad.onion:18081",
    "http://loveanvthlsepingenr7opdqy6nlhn5jidwvzzxfmwsw2rry5mn2gfqd.onion:18089",
    "http://ravfxmrzi3eet62s4nkuu5sgpq6otgtffluk3ylb2kuvimtb34sonryd.onion:18089",
    "http://2cnrtuprdw5ylmnusssmob5ia2tydg6bdtzjce7iyrtl3x4zgi52lrid.onion:18089",
    "http://3gdotfxckfyvyvwogru3vvf4ysgv2v7stplbjinujr2lbh3wxxatayqd.onion:18089",
    "http://hrgzz4caeru4ylcxvfci6pcpbkdzpyowygutuwftjdm52pty2zn3isid.onion:18089",
    "http://doggettpx46kputc5k7dou5su6grtgkycrpsfhvgldrp6cn2rfsdhnad.onion:18089",
    "http://jstark2akepryit2kqfq546s6l7m6jxzaa7x22mzfljuts3xbyorbwqd.onion:18089",
];

/// How many daemons a deposit's check asks (three must agree).
pub const ASKED: usize = 5;

/// One daemon's answer for a transaction: `(daemon id, (block height, its tip height))`, `None` if it does not hold it in
/// a block.
pub type Answer = ([u8; 32], Option<(u64, u64)>);

/// ⭐ The verdict over daemons' answers: the transaction's confirmations when ≥ 3 distinct daemons put it in the SAME block
/// height and none another, counted from the LOWEST tip among them; `None` otherwise (wait, never a majority).
#[must_use]
pub fn verdict(answers: &[Answer]) -> Option<u64> {
    let held: Vec<([u8; 32], [u8; 32])> = answers
        .iter()
        .filter_map(|(d, a)| {
            let (h, _) = (*a)?;
            let mut v = [0u8; 32];
            v[..8].copy_from_slice(&h.to_le_bytes());
            Some((*d, v))
        })
        .collect();
    let Agreement::Agreed(v) = agree(&held) else { return None };
    let height = u64::from_le_bytes(v[..8].try_into().ok()?);
    let tip = answers.iter().filter_map(|(_, a)| (*a).map(|(_, t)| t)).min()?;
    Some(tip.saturating_sub(height))
}

/// The daemons of this node's Monero network.
#[must_use]
pub fn daemons() -> Vec<String> {
    if crate::bridge::xmr_net_byte() == 18 && std::env::var("MONEROUSD_XMR_NET").as_deref() != Ok("regtest") {
        return MAINNET_DAEMONS.iter().map(|s| (*s).to_string()).collect();
    }
    match std::env::var("MONEROUSD_XMR_DAEMON_ONIONS") {
        Ok(v) => v.split(',').map(str::trim).filter(|s| s.contains(".onion")).map(str::to_string).collect(),
        Err(_) => Vec::new(), // none listed: the check cannot reach three daemons, so nothing matures (fail closed)
    }
}

/// Ask one daemon over Tor: the transaction's block height (if it is in a block) and the daemon's tip.
fn ask(agent: &ureq::Agent, base: &str, txid: &str) -> Option<(u64, u64)> {
    let r: serde_json::Value = agent
        .post(&format!("{base}/get_transactions"))
        .send_json(serde_json::json!({ "txs_hashes": [txid] }))
        .ok()?
        .into_json()
        .ok()?;
    let t = r["txs"].as_array()?.first()?;
    if t["in_pool"].as_bool() != Some(false) {
        return None;
    }
    let height = t["block_height"].as_u64()?;
    let h: serde_json::Value = agent.get(&format!("{base}/get_height")).call().ok()?.into_json().ok()?;
    Some((height, h["height"].as_u64()?))
}

/// ⭐ The cross-checked confirmations of `txid` (display hex): the simulator's chain as three honest daemons, else up to
/// [`ASKED`] of this network's onion daemons through the node's Tor. `None` = not (yet) agreed by three.
#[must_use]
pub fn cross_checked_confirmations(txid: &str) -> Option<u64> {
    #[cfg(any(test, feature = "bridge-test-oracle"))]
    if let Some(sim) = crate::xmr_sim::installed() {
        let id: [u8; 32] = crate::btc_tx::unhex(txid)?.try_into().ok()?;
        let s = match sim.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let c = s.tx_confirmations(&id)?;
        let tip = s.tip_height();
        let at = (c > 0).then(|| (tip + 1 - c, tip + 1));
        let answers: Vec<Answer> = (1u8..=3).map(|d| ([d; 32], at)).collect();
        return verdict(&answers);
    }
    // A private regtest chain is one daemon on this machine: there is no second party to cross-check, and no real coin on it. Every other network takes the rule below.
    if std::env::var("MONEROUSD_XMR_NET").as_deref() == Ok("regtest") {
        let base = std::env::var("MONEROUSD_XMR_DAEMON_URL").ok().filter(|u| !u.trim().is_empty())?;
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(10)).build();
        let at = ask(&agent, base.trim_end_matches('/'), txid);
        let answers: Vec<Answer> = (1u8..=3).map(|d| ([d; 32], at)).collect();
        return verdict(&answers);
    }
    let set = daemons();
    if set.len() < crate::btc_filter::MIN_FILTER_PEERS {
        eprintln!("[xmr-watch] fewer than three Monero daemons to cross-check against — no deposit matures (set MONEROUSD_XMR_DAEMON_ONIONS on a test network)");
        return None;
    }
    let agent = crate::btc_watch::agent()?;
    let start = usize::from(blake3::hash(txid.as_bytes()).as_bytes()[0]) % set.len();
    let answers: Vec<Answer> = (0..ASKED.min(set.len()))
        .map(|k| {
            let base = &set[(start + k) % set.len()];
            (*blake3::hash(base.as_bytes()).as_bytes(), ask(&agent, base, txid))
        })
        .collect();
    verdict(&answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐⭐⭐ §22 6 — MONERO DAEMONS CROSS-CHECKED: three daemons putting the transaction in one block count, from the LOWEST of
    /// their tips (a daemon overstating its tip cannot hurry a deposit); two do not; one daemon answering three times is one;
    /// any daemon putting it in another block, or a daemon that does not hold it, stops nothing but its own vote — and a
    /// second height is a conflict that no majority settles.
    /// TWO-PARTY-REVIEWED: the parties are the independent daemons; their crossing is this rule over their answers.
    #[test]
    fn monero_deposits_count_only_when_three_daemons_agree_from_the_lowest_tip() {
        let d = |i: u8| [i; 32];
        assert_eq!(verdict(&[(d(1), Some((100, 120))), (d(2), Some((100, 121))), (d(3), Some((100, 119)))]), Some(19), "lowest tip");
        assert_eq!(verdict(&[(d(1), Some((100, 120))), (d(2), Some((100, 1_000_000)))]), None, "two are not enough");
        assert_eq!(verdict(&[(d(1), Some((100, 120))), (d(1), Some((100, 120))), (d(1), Some((100, 120)))]), None, "one daemon is one");
        assert_eq!(
            verdict(&[(d(1), Some((100, 120))), (d(2), Some((100, 120))), (d(3), Some((100, 120))), (d(4), Some((101, 120)))]),
            None,
            "⛔ a second height is a conflict — no majority"
        );
        assert_eq!(
            verdict(&[(d(1), Some((100, 120))), (d(2), Some((100, 125))), (d(3), Some((100, 130))), (d(4), None)]),
            Some(20),
            "a daemon that does not hold it is no vote"
        );
        assert_eq!(verdict(&[(d(1), Some((100, 9_999))), (d(2), Some((100, 9_999))), (d(3), Some((100, 101)))]), Some(1), "a liar's tip cannot hurry it");
        assert_eq!(MAINNET_DAEMONS.len(), 40);
        assert!(MAINNET_DAEMONS.iter().all(|u| u.starts_with("http://") && u.contains(".onion:")), "onion only");
    }
}
