// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ PROOF TAGS (user 2026-11-09: "optional monerousd proof tags … so businesses can prove income"). A business shows
//! ONE verifier it chooses (a lender, an accountant, a tax office, a partner) what it was paid, and the same bytes
//! prove nothing to anyone the verifier passes them to. Optional in every sense: nothing is made unless the owner asks,
//! no node sees a proof, and no chain byte is written.
//!
//! HOW. The verifier's wallet derives a verifier key and gives it to the business. The business's wallet makes ONE
//! designated-verifier income proof over the notes it holds (`usdm_decider::whir_rec_block::prove_income`): "these
//! notes pay my address and together hold exactly this total", bound to that verifier's key and to a context line (the
//! verifier's reference). The bundle lists the notes' commitments, the total and the proof. More than
//! [`PAY_SUM_MAX_NOTES`] notes are laid as several parts, each with its own proof and its own total.
//!
//! WHAT THE VERIFIER LEARNS: which notes, how many, and their total (per part). Nothing else: not any single amount,
//! not who paid, not the business's other notes, not a nullifier (so not when a note is later spent), not a balance
//! beyond the listed total.
//!
//! WHAT IT DOES NOT PROVE, stated in every check's answer:
//!   * more than its checker's own node says about THE CHAIN. Each listed note names the record it sits in (a public
//!     position every node serves); [`bundle_check`] asks the checker's own node for that record and looks for the
//!     note in it. A note with no known position, or a node that does not answer, is reported as not confirmed and the
//!     answer says how many were.
//!   * that the money came from customers. A business can pay itself from another wallet. What IS left out is this
//!     wallet's own change: a note filed at one of its change locators is never listed as income.
//!   * history. Only notes the wallet holds now are listed; a note already spent is not.
//!
//! OPT-IN, LIVE (user 2026-11-10: "a one click tick in the settings that opts you in and then provides you with the
//! data you need live and on demand with proof anytime"). [`income_summary`] is read from the wallet's own notes each
//! time it is asked, nothing is recorded for it, and a proof is made only when its owner asks for one. The switch is a
//! display preference of the app; with it off the app never calls either function.
//!
//! cons: none on the chain. Off the chain one proof per part; its bytes and milliseconds are measured by the prover's
//! `the_income_proof_is_measured`.

use super::*;
use usdm_decider::whir_rec_block::{pay_verifier_key, prove_income, verify_income, IncomeStatement, PAY_SUM_MAX_NOTES};

const KIND: &str = "musd-income-proof/1";

fn hex_of(d: &Digest4) -> String {
    hex::encode(usdmd_node::spend_frontier::leaf_to_cm_bytes(*d))
}

fn digest_of(h: &str) -> Result<Digest4, String> {
    let b: [u8; 32] = hex::decode(h.trim()).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| "not a 32-byte value".to_string())?;
    usdmd_node::spend_frontier::cm_bytes_to_root(&b).ok_or_else(|| "not a canonical value".to_string())
}

/// The digest a proof binds for a context line: both sides compute it from the line itself.
fn context_digest(context: &str) -> Digest4 {
    usdmd_node::spend_frontier::note_leaf_of(&blake3::derive_key("MonerousD 2026-11-10 proof tag context v1", context.as_bytes()))
}

/// The verifier secret this wallet derives for `label` (one per business it checks). Never stored, never shown.
fn verifier_secret(label: &str) -> Result<Digest4, String> {
    let out_sk = WALLET.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|w| w.out_sk).ok_or_else(|| "no wallet open".to_string())?;
    let key = blake3::derive_key("MonerousD 2026-11-10 proof tag verifier v1", &out_sk);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(label.as_bytes());
    Ok(usdmd_node::spend_frontier::note_leaf_of(h.finalize().as_bytes()))
}

/// VERIFIER: the key to hand a business so it can make proofs only this wallet can rely on.
pub fn verifier_key(label: &str) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({ "label": label, "verifier_key": hex_of(&pay_verifier_key(&verifier_secret(label)?)) }))
}

/// One held note as income sees it: `(amount, seed, commitment, height, record address when known)`.
type Held = (u64, Digest4, [u8; 32], u64, Option<u64>);

/// The statement one part makes: these commitments, this recipient, this total, for `verifier_key` under `context`.
fn part_statement(cms: Vec<Digest4>, total: u64, spk: &Digest4, verifier_key: &Digest4, context: &Digest4) -> IncomeStatement {
    IncomeStatement { cms, recipient_spk: *spk, total, asset_tag: pq::USDM_ASSET_TAG, verifier_key: *verifier_key, context: *context }
}

/// One part of a bundle: up to [`PAY_SUM_MAX_NOTES`] notes, their total, where each sits on the chain when this wallet
/// knows, and ONE proof for `verifier_key` under `context`. No single amount is written.
fn part_make(held: &[Held], spk: &Digest4, verifier_key: &Digest4, context: &Digest4) -> Result<serde_json::Value, String> {
    let cms = held
        .iter()
        .map(|(_, _, cm, ..)| usdmd_node::spend_frontier::cm_bytes_to_root(cm).ok_or_else(|| "a held note's commitment is not canonical".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let total = held.iter().try_fold(0u64, |sum, (amount, ..)| sum.checked_add(*amount)).ok_or_else(|| "the total does not fit".to_string())?;
    let openings: Vec<(u64, Digest4)> = held.iter().map(|(amount, seed, ..)| (*amount, *seed)).collect();
    let proof = prove_income(&part_statement(cms, total, spk, verifier_key, context), &openings)
        .ok_or_else(|| "a held note did not open to its commitment, so nothing was proven".to_string())?;
    // a record address travels as text: it is larger than a JSON number holds exactly
    let notes: Vec<serde_json::Value> =
        held.iter().map(|(_, _, cm, _, record)| serde_json::json!({ "cm": hex::encode(cm), "record": record.map(|r| r.to_string()) })).collect();
    Ok(serde_json::json!({ "total_atomic": total, "notes": notes, "proof": hex::encode(proof) }))
}

/// The commitments this wallet filed at its OWN change locators: money that came back from its own spends, not income.
/// Read from the locator bridge the detection pass keeps in memory.
fn own_change() -> std::collections::HashSet<[u8; 32]> {
    LOC_BY_CM.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(_, (dom, _))| is_chg_domain(dom)).map(|(cm, _)| *cm).collect()
}

/// The USDm notes this wallet was PAID and still holds (its own change left out), narrowed to one charge's notes when
/// `reference` is given. Read from the owned set as it stands (the app's own balance pass keeps it current).
fn held_notes(reference: Option<[u8; 16]>) -> Result<Vec<Held>, String> {
    let dk = own_scan_dk()?;
    let change = own_change();
    let s = SCAN.lock().unwrap_or_else(|e| e.into_inner());
    Ok(s.as_ref()
        .map(|st| {
            st.owned
                .iter()
                .filter(|n| n.asset == pq::USDM_ASSET_TAG && n.note.len() >= 32)
                .filter(|n| reference.as_ref().is_none_or(|r| pq::note_carries_reference(&n.note, &dk, r)))
                .filter_map(|n| <[u8; 32]>::try_from(&n.note[..32]).ok().map(|cm| (n.amount, n.seed, cm, n.height)))
                .filter(|(_, _, cm, _)| !change.contains(cm))
                // where the note sits: the record address this wallet confirmed for it (a public position)
                .map(|(amount, seed, cm, height)| (amount, seed, cm, height, st.da_pos.get(&cm).map(|pos| pos.0).filter(|addr| *addr != u64::MAX)))
                .collect()
        })
        .unwrap_or_default())
}

/// LIVE: what this wallet was paid and holds now. The count, the total, and the latest few payments, newest first.
pub fn income_summary() -> Result<serde_json::Value, String> {
    let mut held = held_notes(None)?;
    let total = held.iter().try_fold(0u64, |sum, (amount, ..)| sum.checked_add(*amount)).ok_or_else(|| "the total does not fit".to_string())?;
    // a note whose height is not placed yet (the wallet's own "unknown" marker) is the newest
    held.sort_by_key(|(_, _, _, height, _)| std::cmp::Reverse(*height));
    let latest: Vec<serde_json::Value> = held
        .iter()
        .take(5)
        .map(|(amount, _, _, height, _)| serde_json::json!({ "amount": amount, "height": if *height == u64::MAX { serde_json::Value::Null } else { serde_json::json!(height) } }))
        .collect();
    Ok(serde_json::json!({ "payments": held.len(), "total_atomic": total, "total_usdm": atomic_to_usdm(total), "latest": latest }))
}

/// The verifier key a bundle is made for: a named verifier's key, or (for an empty key or the word `public`) the key
/// nobody holds, under which anyone may check the proof.
fn verifier_of(key_hex: &str) -> Result<Digest4, String> {
    match key_hex.trim() {
        "" | "public" => Ok(usdm_decider::whir_rec_block::public_verifier_key()),
        hex => digest_of(hex),
    }
}

/// BUSINESS: proof tags for the USDm notes this wallet holds, for one verifier. `reference` narrows the bundle to the
/// notes that paid one charge (an order's signed nonce), so a single sale can be shown without the rest.
pub fn bundle_make(verifier_key_hex: &str, context: &str, reference: Option<[u8; 16]>) -> Result<serde_json::Value, String> {
    let verifier_key = verifier_of(verifier_key_hex)?;
    let keys = own_note_keys()?;
    let held = held_notes(reference)?;
    if held.is_empty() {
        return Err("this wallet holds no note to show for that".to_string());
    }
    let ctx = context_digest(context);
    let parts = held.chunks(PAY_SUM_MAX_NOTES).map(|part| part_make(part, &keys.spk, &verifier_key, &ctx)).collect::<Result<Vec<_>, _>>()?;
    let total = held.iter().try_fold(0u64, |sum, (amount, ..)| sum.checked_add(*amount)).ok_or_else(|| "the total does not fit".to_string())?;
    Ok(serde_json::json!({
        "kind": KIND, "recipient_spk": hex_of(&keys.spk), "verifier_key": hex_of(&verifier_key), "context": context,
        "total_atomic": total, "parts": parts,
    }))
}

/// The parts of a bundle, as a list. A bundle with none is refused by its checker.
fn parts_of(bundle: &serde_json::Value) -> Vec<serde_json::Value> {
    bundle.get("parts").and_then(|p| p.as_array()).cloned().unwrap_or_default()
}

/// One part of a bundle, checked: its commitments and its total. An error names what failed.
fn check_part(i: usize, part: &serde_json::Value, spk: &Digest4, mine: &Digest4, ctx: &Digest4) -> Result<(Vec<Digest4>, u64), String> {
    let total = part.get("total_atomic").and_then(|v| v.as_u64()).ok_or_else(|| format!("part {i} has no total"))?;
    let proof = part.get("proof").and_then(|v| v.as_str()).and_then(|p| hex::decode(p).ok()).ok_or_else(|| format!("part {i} has no proof"))?;
    let notes = part.get("notes").and_then(|n| n.as_array()).filter(|n| !n.is_empty()).ok_or_else(|| format!("part {i} lists no note"))?;
    let cms = notes
        .iter()
        .map(|n| n.get("cm").and_then(|v| v.as_str()).ok_or(()).and_then(|h| digest_of(h).map_err(|_| ())))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| format!("part {i} lists a malformed commitment"))?;
    if !verify_income(&proof, &part_statement(cms.clone(), total, spk, mine, ctx)) {
        return Err(format!("part {i} does not prove its stated total"));
    }
    Ok((cms, total))
}

/// The statements of a bundle, checked against the verifier key `mine`: `(notes, total)`. Every part must verify for
/// exactly its total under the bundle's recipient and context, no note may be listed twice anywhere in the bundle, and
/// the parts' totals must sum to the stated total. Anything else is an error naming what failed; there is no partial
/// pass.
fn check_statements(bundle: &serde_json::Value, mine: &Digest4) -> Result<(usize, u64), String> {
    let text = |k: &str| bundle.get(k).and_then(|v| v.as_str()).ok_or_else(|| format!("the bundle has no `{k}`"));
    if text("kind")? != KIND {
        return Err("that is not a proof of income".to_string());
    }
    if digest_of(text("verifier_key")?)? != *mine {
        return Err("this proof was made for another verifier, so it proves nothing to you".to_string());
    }
    let spk = digest_of(text("recipient_spk")?)?;
    let ctx = context_digest(text("context")?);
    let parts = parts_of(bundle);
    if parts.is_empty() {
        return Err("the bundle lists no note".to_string());
    }
    let checked = parts.iter().enumerate().map(|(i, p)| check_part(i, p, &spk, mine, &ctx)).collect::<Result<Vec<_>, _>>()?;
    let listed: Vec<Digest4> = checked.iter().flat_map(|(cms, _)| cms.iter().copied()).collect();
    let distinct: std::collections::HashSet<Digest4> = listed.iter().copied().collect();
    if distinct.len() != listed.len() {
        return Err("a note is listed twice: the same money counted again".to_string());
    }
    let total = checked.iter().try_fold(0u64, |sum, (_, t)| sum.checked_add(*t)).ok_or_else(|| "the total does not fit".to_string())?;
    if bundle.get("total_atomic").and_then(|t| t.as_u64()) != Some(total) {
        return Err("the stated total is not the sum of the parts".to_string());
    }
    Ok((listed.len(), total))
}

/// Does the record at `addr`, as THIS wallet's own node serves it, hold the note `cm`, and has that record folded?
/// `None` when the node does not answer. The ask names a public record address, never a note, key or owner.
fn record_holds(addr: u64, cm: &[u8]) -> Option<bool> {
    let v = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .build()
        .post(&format!("{}/da_record", node_url()))
        .send_json(serde_json::json!({ "addr": addr }))
        .ok()?
        .into_json::<serde_json::Value>()
        .ok()?;
    let notes = hex::decode(v.get("notes_hex")?.as_str()?).ok()?;
    let folded = v.get("ordinal").and_then(serde_json::Value::as_u64).is_some();
    Some(folded && notes.chunks_exact(usdmd_node::cover::PQ_NOTE_BYTES).any(|n| n[..32] == cm[..]))
}

/// How many of a bundle's notes this wallet's own node confirms on the chain, of how many are listed.
fn confirmed_on_chain(bundle: &serde_json::Value) -> (usize, usize) {
    let notes: Vec<serde_json::Value> =
        parts_of(bundle).iter().flat_map(|p| p.get("notes").and_then(|n| n.as_array()).cloned().unwrap_or_default()).collect();
    let confirmed = notes
        .iter()
        .filter(|n| {
            let cm = n.get("cm").and_then(|c| c.as_str()).and_then(|c| hex::decode(c).ok());
            let addr = n.get("record").and_then(|r| r.as_str()).and_then(|r| r.parse::<u64>().ok());
            matches!((cm, addr), (Some(cm), Some(addr)) if cm.len() == 32 && record_holds(addr, &cm) == Some(true))
        })
        .count();
    (confirmed, notes.len())
}

/// VERIFIER: check a bundle made for this wallet's `label` key. The answer says in words what was and was not checked.
pub fn bundle_check(bundle: &serde_json::Value, label: &str) -> Result<serde_json::Value, String> {
    // a proof made for anyone is checked under the key nobody holds; any other only under this wallet's own key
    let public = usdm_decider::whir_rec_block::public_verifier_key();
    let for_anyone = bundle.get("verifier_key").and_then(|k| k.as_str()).is_some_and(|k| digest_of(k).ok() == Some(public));
    let mine = if for_anyone { public } else { pay_verifier_key(&verifier_secret(label)?) };
    let (notes, total) = check_statements(bundle, &mine)?;
    let (confirmed, listed) = confirmed_on_chain(bundle);
    let chain = if confirmed == listed { "all" } else if confirmed == 0 { "none" } else { "some" };
    Ok(serde_json::json!({
        "statements_valid": true,
        "notes": notes,
        "total_atomic": total,
        "total_usdm": atomic_to_usdm(total),
        "recipient_spk": bundle.get("recipient_spk").cloned().unwrap_or_default(),
        "context": bundle.get("context").cloned().unwrap_or_default(),
        "for_anyone": for_anyone,
        "on_chain": chain,
        "confirmed": confirmed,
        "means": format!(
            "The listed payments were made to this address and together hold exactly this total; no single amount is shown. Your own node confirms {confirmed} of {listed} of them on the chain. Money a business paid itself looks the same as money from a customer."
        ),
    }))
}

#[tauri::command]
pub async fn proof_tag_verifier_key(label: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || verifier_key(&label)).await.map_err(|e| format!("proof_tag_verifier_key task failed: {e}"))?
}

/// ⛔ OFF UNLESS THE OWNER TURNED IT ON, AND OFF AGAIN AT EVERY START (user 2026-11-10: "the proof of income should always
/// be off by default and opt in because it removes some privacy. it should only track income when on, never by
/// default"). Held in memory only: a wallet that was just opened has it off whatever it was last time, and nothing about
/// income is computed, shown or proven while it is off. The app's commands below refuse when it is off, so the switch is
/// enforced here in the core and not by the page.
static OPTED_IN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Is proof of income on for this session?
pub fn opted_in() -> bool {
    OPTED_IN.load(std::sync::atomic::Ordering::SeqCst)
}

/// Turn proof of income on or off for this session.
pub fn set_opt_in(on: bool) {
    OPTED_IN.store(on, std::sync::atomic::Ordering::SeqCst);
}

fn require_opt_in() -> Result<(), String> {
    if opted_in() {
        Ok(())
    } else {
        Err("Proof of income is off. Turn it on in Settings first.".to_string())
    }
}

#[tauri::command]
pub fn proof_tags_state() -> serde_json::Value {
    serde_json::json!({ "on": opted_in() })
}

/// The switch. Turning it ON asks the owner first, in words that say what it gives up; turning it off asks nothing.
#[tauri::command]
pub async fn proof_tags_set(on: bool) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if on && !opted_in() {
            require_user_approval(
                "Turn on proof of income: this wallet will work out what you were paid and can make proofs of it. Anyone you give a proof to learns those amounts."
                    .to_string(),
            )?;
        }
        set_opt_in(on);
        Ok(serde_json::json!({ "on": on }))
    })
    .await
    .map_err(|e| format!("proof_tags_set task failed: {e}"))?
}

#[tauri::command]
pub async fn proof_tags_income() -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        require_opt_in()?;
        income_summary()
    })
    .await
    .map_err(|e| format!("proof_tags_income task failed: {e}"))?
}

#[tauri::command]
pub async fn proof_tags_make(verifier_key: String, context: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        require_opt_in()?;
        let who = if matches!(verifier_key.trim(), "" | "public") { "anyone you send it to" } else { "one verifier" };
        require_user_approval(format!("Show {who} the amounts you were paid and hold ({})", approval_short(&context, 40)))?;
        bundle_make(&verifier_key, &context, None)
    })
    .await
    .map_err(|e| format!("proof_tags_make task failed: {e}"))?
}

#[tauri::command]
pub async fn proof_tags_check(bundle: serde_json::Value, label: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || bundle_check(&bundle, &label)).await.map_err(|e| format!("proof_tags_check task failed: {e}"))?
}

// TWO-PARTY-REVIEWED: the test below builds real proofs with the prover and checks them with the verifier's own
// function under a second key; the business's wallet and the verifier's wallet as two processes on real nodes belong
// in the real-node check scratchpad/net/goods.py (its proof-tag step is not written yet).
#[cfg(test)]
mod tests {
    use super::*;
    use usdm_decider::whir_rec_block::{payment_note_cm, PaymentStatement};

    /// Real notes of one recipient, made without a wallet: the chain's own spelling of each commitment.
    fn held_for(spk: &Digest4, tag: &str, amounts: &[u64]) -> Vec<Held> {
        let leaf = |t: &[u8]| usdmd_node::spend_frontier::note_leaf_of(blake3::hash(t).as_bytes());
        amounts
            .iter()
            .enumerate()
            .map(|(i, amount)| {
                let seed = leaf(format!("{tag} seed {i}").as_bytes());
                let st = PaymentStatement { cm: *spk, recipient_spk: *spk, amount: *amount, asset_tag: pq::USDM_ASSET_TAG, verifier_key: *spk, context: *spk };
                (*amount, seed, usdmd_node::spend_frontier::leaf_to_cm_bytes(payment_note_cm(&st, &seed)), 0u64, None)
            })
            .collect()
    }

    /// A bundle with one real part per list of amounts: the same statements and the same prover the wallet uses.
    fn bundle_for(vsk: &Digest4, parts: &[&[u64]]) -> (serde_json::Value, Digest4) {
        let spk = usdmd_node::spend_frontier::note_leaf_of(blake3::hash(b"recipient").as_bytes());
        let (vk, ctx_line) = (pay_verifier_key(vsk), "loan 7781");
        let ctx = context_digest(ctx_line);
        let made: Vec<serde_json::Value> =
            parts.iter().enumerate().map(|(p, amounts)| part_make(&held_for(&spk, &format!("part {p}"), amounts), &spk, &vk, &ctx).expect("real notes prove")).collect();
        let total: u64 = parts.iter().flat_map(|a| a.iter()).sum();
        (serde_json::json!({ "kind": KIND, "recipient_spk": hex_of(&spk), "verifier_key": hex_of(&vk), "context": ctx_line, "total_atomic": total, "parts": made }), vk)
    }

    #[test]
    fn a_bundle_checks_for_its_verifier_alone_and_every_lie_in_it_is_refused() {
        let vsk = usdmd_node::spend_frontier::note_leaf_of(blake3::hash(b"the verifier's secret").as_bytes());
        let (bundle, vk) = bundle_for(&vsk, &[&[2_500_000_000, 700_000_000], &[100_000_000]]);
        assert_eq!(check_statements(&bundle, &vk), Ok((3, 3_300_000_000)));
        // no single amount is written anywhere in it: not as a number or a decimal string in any field, and not as
        // its eight bytes inside a proof (the form a leaked witness cell would take). A proof's hex is not searched for
        // decimal digits: a small integer in a proof's own framing reads as "07000000 00…" and means nothing.
        fn fields(v: &serde_json::Value, out: &mut Vec<String>, proofs: &mut Vec<Vec<u8>>) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, x) in m {
                        match (k.as_str(), x.as_str()) {
                            ("proof", Some(hex)) => proofs.push(hex::decode(hex).expect("a proof is hex")),
                            _ => fields(x, out, proofs),
                        }
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(|x| fields(x, out, proofs)),
                other => out.push(other.to_string()),
            }
        }
        let (mut said, mut proofs) = (Vec::new(), Vec::new());
        fields(&bundle, &mut said, &mut proofs);
        assert_eq!(proofs.len(), 2, "one proof a part");
        for amount in [2_500_000_000u64, 700_000_000] {
            assert!(!said.iter().any(|f| f.contains(&amount.to_string())), "a note's own amount is written in the bundle");
            assert!(!proofs.iter().any(|p| p.windows(8).any(|w| w == amount.to_le_bytes())), "a note's own amount is in a proof's bytes");
        }

        // another verifier: the same bytes prove nothing
        let other = pay_verifier_key(&usdmd_node::spend_frontier::note_leaf_of(blake3::hash(b"someone else").as_bytes()));
        assert!(check_statements(&bundle, &other).is_err());

        let lie = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut b = bundle.clone();
            edit(&mut b);
            check_statements(&b, &vk)
        };
        // a larger total on one part, with the bundle's total adjusted to match
        assert!(lie(&|b| { b["parts"][0]["total_atomic"] = serde_json::json!(9_500_000_000u64); b["total_atomic"] = serde_json::json!(9_600_000_000u64); }).is_err());
        // a larger bundle total alone
        assert!(lie(&|b| b["total_atomic"] = serde_json::json!(3_300_000_001u64)).is_err());
        // one part counted twice (every note in it listed twice)
        assert!(lie(&|b| { let p = b["parts"][1].clone(); b["parts"].as_array_mut().unwrap().push(p); b["total_atomic"] = serde_json::json!(3_400_000_000u64); }).is_err());
        // a note dropped from a part's list, or another note named in its place
        assert!(lie(&|b| { b["parts"][0]["notes"].as_array_mut().unwrap().pop(); }).is_err());
        assert!(lie(&|b| b["parts"][0]["notes"][0]["cm"] = b["parts"][1]["notes"][0]["cm"].clone()).is_err());
        // another context, another recipient, another part's proof
        assert!(lie(&|b| b["context"] = serde_json::json!("loan 7782")).is_err());
        assert!(lie(&|b| b["recipient_spk"] = b["verifier_key"].clone()).is_err());
        assert!(lie(&|b| { let p = b["parts"][1]["proof"].clone(); b["parts"][0]["proof"] = p; }).is_err());
        // nothing listed
        assert!(lie(&|b| b["parts"] = serde_json::json!([])).is_err());
    }
}
