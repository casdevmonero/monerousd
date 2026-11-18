// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! PAY A @USERNAME WITHOUT LINKING ANYTHING TO IT (user 2026-11-10: "could usernames be made untraceable by using
//! subaddresses behind the front facing username? if so build it").
//!
//! WHAT A NAME WAS. The chain's directory binds a name to its owner's PUBLISHED address, the one with no locator
//! (a locator in a published address would let anyone watch every payment to it). A note paid to an address with no
//! locator has no place its owner can find it by, so its owner can neither spend it nor recover it from the recovery
//! phrase (audit F11, measured on three real nodes); the send door has refused such a payment since. A name could be
//! looked up and could not be paid.
//!
//! WHAT A NAME IS NOW: A FRONT DOOR. The name still resolves, on the chain, to its owner's published address. That
//! address is never paid. The payer's wallet writes to it, as a sealed letter, "give me an address"; the payee's
//! wallet answers with a receive address made for that one payer (its own keys and its own locator,
//! `pq::receive_address_of`), and the payer pays THAT. Nothing on the chain names the name: the two letters are
//! opaque ciphertext in the constant letter slots, and the payment is an ordinary note to an address nobody else holds.
//!
//! WHO LEARNS WHAT.
//! * The chain and every node: nothing. Two sealed letters like any others; one payment like any other.
//! * The payee: that somebody asked, and then (as with any payment) that a payment arrived. NOT who: the ask is
//!   sealed and signed under a throwaway identity the payer derives for this one ask (`ask_identity`), so the
//!   payee's reply goes to an address that exists for one letter.
//! * The payer: one address. It shares no byte with any other address of the payee's, so two payers of one name
//!   cannot tell from their addresses that they pay one wallet beyond what the name already told them, and neither can
//!   watch the other's payment (each locator is its payer's alone).
//! * Another payer of the same name, or any observer: nothing about this payment.
//!
//! THE ANSWER IS THE PAYEE'S, BY THE CHAIN. A letter opens only if its sender signed it under the spend key its
//! claimed address is bound to (`letter::open_authenticated`). The payer accepts an answer only from the address the
//! chain's directory holds for the name and only for its own ask's nonce, so a relay, a node or another wallet cannot
//! hand it an address of its own.
//!
//! THE PAYEE'S WALLET MUST BE REACHABLE. An address has to be made by the wallet that will receive: the payee's
//! wallet answers while it is open (its letter sync, `sale::sync`). A payer whose ask is not answered in time is told
//! so, in words, and nothing is spent; its wallet remembers the ask and the next try takes the answer if it has come.
//!
//! NO ADDRESS IS HANDED TO TWO ASKS. The payee's wallet issues by the wallet's one receive rule (`recv_issue`: a new
//! index opens only above ranges a payment has anchored, so a recovery phrase finds every address ever handed out).
//! When the rule has no fresh index it answers "busy" rather than repeat one, and anchors the range itself with a
//! minimal payment to its own newest address so the next range opens (one network fee; asked for at most once per
//! address). A wallet that has never been paid has one address to give; its first payment opens the second.
//!
//! cons: a payment by name waits for the payee's wallet (seconds when it is open; not at all while it is closed);
//! two letters per payment; the payee pays one network fee each time asks outrun its anchored ranges (the ranges
//! double, so n asks cost about log2(n) fees); a flood of asks makes the payee's wallet write answers and can keep
//! payers by name waiting behind it until a range anchors (paying the payee's own Receive address is unaffected).
use super::*;
use std::collections::HashMap;
use std::sync::LazyLock;

const HEAD: &str = "musd-addr/1 ";

/// One ask this wallet has out: its nonce and the answer once it came.
struct Asking {
    nonce: [u8; 16],
    answer: Option<String>,
}

/// PAYER: the ask out for each name, by canonical name. O1-FOOTPRINT-REVIEWED: one entry per name this session paid.
static ASKING: LazyLock<Mutex<HashMap<String, Asking>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// PAYEE: the address index handed to each ask, by `(asker address, nonce)`: the same ask asked again gets the same
/// address. O1-FOOTPRINT-REVIEWED: one entry per ask answered this session.
static GIVEN: LazyLock<Mutex<HashMap<(String, String), u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// PAYEE: the receive index this wallet last anchored by itself (so one stuck index asks for one self-payment).
static SELF_ANCHORED: AtomicU64 = AtomicU64::new(u64::MAX);
/// PAYEE: letters already answered this session, by content hash.
static DONE: LazyLock<Mutex<std::collections::HashSet<String>>> = LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The throwaway identity one ask is sealed and signed under: a whole key set derived from this wallet's outgoing
/// secret and the ask's nonce. The payee sees this identity and nothing of the wallet behind it; this wallet
/// re-derives it to open the answer.
fn ask_identity(nonce: &[u8; 16]) -> Result<pq::WalletKeys, String> {
    let out_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.out_sk).ok_or_else(|| "no wallet open".to_string())?;
    let mut h = blake3::Hasher::new_keyed(&out_sk);
    h.update(b"MonerousD 2026-11-10 pay-name ask identity v1");
    h.update(nonce);
    Ok(pq::derive_keys(h.finalize().as_bytes()))
}

fn post_letter(blob: &[u8]) -> Result<(), String> {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build()
        .post(&format!("{}/letter/send", node_url()))
        .send_json(serde_json::json!({ "blob": hex::encode(blob) }))
        .map_err(|e| format!("your node did not take the letter: {}", node_refusal(e)))?;
    Ok(())
}

/// The node's current letter slots, opened under the given keys: `(from, message)` of every letter that is theirs.
fn inbox_under(ek: &[u8], dk: &[u8]) -> Vec<(String, String)> {
    let Ok(resp) = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build().get(&format!("{}/letter/inbox", node_url())).call() else {
        return Vec::new();
    };
    let Ok(v) = resp.into_json::<serde_json::Value>() else { return Vec::new() };
    v.get("slots")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
        .filter_map(|s| hex::decode(s.as_str()?).ok())
        .filter_map(|blob| crate::letter::open_authenticated(&blob, ek, dk))
        .map(|o| (o.from_addr, String::from_utf8_lossy(&o.msg).to_string()))
        .collect()
}

/// An address fit to pay: it parses, it carries a locator (its owner can find and spend what lands there) and a spend
/// key. The payee's word is not taken for it.
fn payable(address: &str) -> bool {
    usdmd_node::address::parse_address_full(address).is_some_and(|a| a.locator.is_some() && a.spk.is_some())
}

/// PAYER: the one-time address the payee behind `name` gives THIS payment. `payee_address` is what the chain's
/// directory holds for the name (the published, never-paid address); the answer is taken only from it and only for
/// this wallet's own ask. Asks once per name per session and waits up to `wait` for the answer; an answer that came
/// after an earlier wait is taken at once.
pub fn one_time_address(name: &str, payee_address: &str, wait: Duration) -> Result<String, String> {
    let nonce = {
        let mut asking = locked(&ASKING);
        if let Some(a) = asking.get(name) {
            if let Some(address) = &a.answer {
                return Ok(address.clone());
            }
            a.nonce
        } else {
            use rand::RngCore as _;
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            asking.insert(name.to_string(), Asking { nonce, answer: None });
            nonce
        }
    };
    let me = ask_identity(&nonce)?;
    let ask = format!("{HEAD}ask {}", serde_json::json!({ "n": hex::encode(nonce) }));
    let blob = crate::letter::seal(payee_address, &me, &me.handle_address, ask.as_bytes())
        .ok_or_else(|| format!("@{name}'s address on the chain cannot be written to"))?;
    post_letter(&blob)?;
    let started = Instant::now();
    let mut busy = false;
    loop {
        for (from, msg) in inbox_under(&me.scan_ek, &me.scan_dk) {
            // only the address the chain holds for the name, only this ask
            if from != payee_address {
                continue;
            }
            let Some((kind, body)) = msg.strip_prefix(HEAD).and_then(|r| r.split_once(' ')) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else { continue };
            if v.get("n").and_then(|n| n.as_str()) != Some(hex::encode(nonce).as_str()) {
                continue;
            }
            match kind {
                "give" => {
                    let Some(address) = v.get("a").and_then(|a| a.as_str()).filter(|a| payable(a)) else { continue };
                    if let Some(a) = locked(&ASKING).get_mut(name) {
                        a.answer = Some(address.to_string());
                    }
                    return Ok(address.to_string());
                }
                "busy" => busy = true,
                _ => {}
            }
        }
        if started.elapsed() >= wait {
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    Err(if busy {
        format!("@{name}'s wallet is giving out its addresses to other payers right now. Nothing was sent. Try again in a minute.")
    } else {
        format!(
            "@{name}'s wallet has not answered yet. To be paid by name its owner's wallet must be open, because it makes a new address for every payer. Nothing was sent. Try again in a minute, or ask them for the address on their Receive page."
        )
    })
}

/// PAYER: the payment to `name` was sent to the address it was given: the next payment to that name asks again (one
/// address, one payment).
pub fn paid(name: &str) {
    locked(&ASKING).remove(name);
}

/// PAYEE: answer every ask in this wallet's opened letters (`messages`: the inbox's `{from, msg, cm}` rows). Each ask
/// gets a fresh receive address by the wallet's own issuance rule, or "busy" when the rule has none to give. Returns
/// what was done, in words (nothing about who asked: the wallet does not know).
pub fn answer_asks(messages: &[serde_json::Value]) -> Vec<String> {
    let mut said = Vec::new();
    for m in messages {
        let (Some(from), Some(msg), Some(cm)) = (m.get("from").and_then(|x| x.as_str()), m.get("msg").and_then(|x| x.as_str()), m.get("cm").and_then(|x| x.as_str())) else {
            continue;
        };
        let Some(body) = msg.strip_prefix(HEAD).and_then(|r| r.strip_prefix("ask ")) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else { continue };
        let Some(n) = v.get("n").and_then(|n| n.as_str()).filter(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit())) else { continue };
        if !locked(&DONE).insert(cm.to_string()) {
            continue;
        }
        let given = locked(&GIVEN).get(&(from.to_string(), n.to_string())).copied();
        let index = match given {
            Some(j) => Some(j),
            None => fresh_index(),
        };
        let reply = match index.and_then(|j| address_at(j).map(|a| (j, a))) {
            Some((j, address)) => {
                locked(&GIVEN).insert((from.to_string(), n.to_string()), j);
                said.push("Someone asked to pay you by name and was given a new address.".to_string());
                format!("{HEAD}give {}", serde_json::json!({ "n": n, "a": address }))
            }
            None => {
                said.extend(anchor_own_range());
                format!("{HEAD}busy {}", serde_json::json!({ "n": n }))
            }
        };
        if letter_send_impl(from, &reply).is_err() {
            // not answered: looked at again on the next pass
            locked(&DONE).remove(cm);
        }
    }
    said
}

/// PAYEE: the next receive index nobody has been handed, by the wallet's one issuance rule; `None` when the rule has
/// no fresh index (the range above is not anchored yet).
fn fresh_index() -> Option<u64> {
    let loc_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.loc_sk)?;
    let (j, fresh) = recv_issue(current_receive_index(&loc_sk), RECV_ANCHORED.load(Ordering::SeqCst));
    if !fresh {
        return None;
    }
    LOC_NEXT_RECV.store(j, Ordering::SeqCst);
    Some(j)
}

fn address_at(j: u64) -> Option<String> {
    let g = WALLET.lock().unwrap_or_else(|e| e.into_inner());
    pq::receive_address_of(g.as_ref()?, j)
}

/// PAYEE: asks have outrun the ranges this wallet's payments anchored. Anchor the newest range with the smallest
/// payment to this wallet's own newest address, so the range above opens and the payers waiting are answered on a
/// later pass. Once per address; needs a spendable note for the fee, and says so when there is none.
fn anchor_own_range() -> Option<String> {
    let loc_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.loc_sk)?;
    let j = current_receive_index(&loc_sk);
    if j == 0 || SELF_ANCHORED.swap(j, Ordering::SeqCst) == j {
        return None; // address 0 is the wallet's base address (its first payment anchors it); or already asked for
    }
    let address = address_at(j)?;
    match do_transfer_atomic(address, 1) {
        Ok(_) => Some("More people asked to pay you by name than you had addresses ready, so your wallet opened more (one network fee).".to_string()),
        Err(e) => {
            SELF_ANCHORED.store(u64::MAX, Ordering::SeqCst);
            Some(format!("More people asked to pay you by name than you had addresses ready, and your wallet could not open more: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE HANDSHAKE BETWEEN TWO WALLETS, AND AN ADVERSARY BETWEEN THEM. The payer's ask is sealed and signed under its
    /// throwaway identity; the payee (the name's owner, a second key set) opens it and learns that identity and nothing
    /// of the payer's wallet; the payee's answer opens only under the ask's identity and authenticates as the payee's
    /// published address; an adversary's answer (a third wallet that also knows the nonce) authenticates as the
    /// adversary's address, which is not the one the chain holds for the name, so the payer's rule refuses it.
    #[test]
    fn the_payee_answers_an_ask_it_cannot_trace_and_an_adversarys_answer_is_not_the_payees() {
        let payer_wallet = pq::derive_keys(&[0x61u8; 32]);
        let payee = pq::derive_keys(&[0x62u8; 32]);
        let adversary = pq::derive_keys(&[0x63u8; 32]);
        let payer_own = (payer_wallet.scan_ek.clone(), payer_wallet.spend_pk.clone(), payer_wallet.handle_address.clone());
        *WALLET.lock().unwrap_or_else(|e| e.into_inner()) = Some(payer_wallet);
        let nonce = [7u8; 16];
        let (me, again, other) = (ask_identity(&nonce).unwrap(), ask_identity(&nonce).unwrap(), ask_identity(&[8u8; 16]).unwrap());
        *WALLET.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // the ask's identity: re-derivable by the payer, its own per ask, nothing of the payer's wallet
        assert_eq!(me.handle_address, again.handle_address, "the same ask is the same identity (a later try opens its answer)");
        assert_ne!(me.handle_address, other.handle_address, "two asks are two identities");
        assert_ne!(me.scan_ek, payer_own.0, "an ask's key is not the payer's");
        assert_ne!(me.spend_pk, payer_own.1, "an ask signs under its own key");
        assert_ne!(me.handle_address, payer_own.2, "an ask's address is not the payer's");
        // payer -> payee
        let ask = format!("{HEAD}ask {}", serde_json::json!({ "n": hex::encode(nonce) }));
        let blob = crate::letter::seal(&payee.handle_address, &me, &me.handle_address, ask.as_bytes()).expect("the ask seals");
        let at_payee = crate::letter::open_authenticated(&blob, &payee.scan_ek, &payee.scan_dk).expect("the payee opens the ask");
        assert_eq!(at_payee.from_addr, me.handle_address, "the payee sees the ask's identity");
        assert_ne!(at_payee.from_addr, payer_own.2, "⛔ the payee learned the payer's own address");
        assert!(crate::letter::open_authenticated(&blob, &adversary.scan_ek, &adversary.scan_dk).is_none(), "⛔ a third wallet opened the ask");
        // payee -> payer: a fresh address, one the payee can find and spend
        let given = pq::receive_address_of(&payee, 5).expect("the payee's address 5");
        assert!(payable(&given) && !payable(&payee.handle_address), "the published address is never the answer");
        let give = format!("{HEAD}give {}", serde_json::json!({ "n": hex::encode(nonce), "a": given }));
        let reply = crate::letter::seal(&at_payee.from_addr, &payee, &payee.handle_address, give.as_bytes()).expect("the answer seals");
        let at_payer = crate::letter::open_authenticated(&reply, &me.scan_ek, &me.scan_dk).expect("the payer opens the answer under the ask's identity");
        assert_eq!(at_payer.from_addr, payee.handle_address, "the answer authenticates as the address the chain holds for the name");
        // the adversary answers the same ask with an address of its own: it authenticates as the adversary
        let theirs = pq::receive_address_of(&adversary, 1).expect("the adversary's address");
        let forged = format!("{HEAD}give {}", serde_json::json!({ "n": hex::encode(nonce), "a": theirs }));
        let forged = crate::letter::seal(&me.handle_address, &adversary, &adversary.handle_address, forged.as_bytes()).expect("seals");
        let seen = crate::letter::open_authenticated(&forged, &me.scan_ek, &me.scan_dk).expect("it opens: the adversary can write to the ask's address");
        assert_ne!(seen.from_addr, payee.handle_address, "⛔ an adversary's answer authenticated as the payee's");
        // and it cannot claim the payee's address: a letter naming an address its signer's key is not bound to does not open
        let lying = crate::letter::seal(&me.handle_address, &adversary, &payee.handle_address, b"x").expect("seals");
        assert!(crate::letter::open_authenticated(&lying, &me.scan_ek, &me.scan_dk).is_none(), "⛔ a letter claiming the payee's address under another key opened");
    }
}
