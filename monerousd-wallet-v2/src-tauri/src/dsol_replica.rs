// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ A BACK END'S STORAGE, READ FROM THE CHAIN IN ONE LOOKUP (D4, Veil spec §12).
//!
//! The chain holds a contract's storage ROOT. Every applied call carries the contract's WHOLE post-state sealed under the
//! contract's key `k_c`, proven from the empty trie to the call's `storage_post` (`usdm_decider::dsol_blob_air`), and every
//! node keeps each contract's last few such records (`usdmd_node::contract_blobs`, `/contract_state_blob`). A wallet that
//! holds `k_c` (the deployer, from its seed; a site's users, from the site) reads the state here: it decrypts the newest
//! record, and accepts it only when its slots fold to the root the chain's contract leaf holds NOW
//! (`manifest.leaf(root) == chain_leaf`). Nothing is replayed: the newest call IS the state. When the node holds no
//! record (a contract never called reads as the empty trie; one its node's store let go reads from the site's own sealed
//! snapshot, `.veil/state/<cid>`), the same check decides.
//!
//! What protects it (AI RESISTANT): (a) — the state accepted is the chain's own root; the blob's contents were proven by
//! the door before the chain applied them. A node that withholds or serves garbage cannot make the wallet accept a wrong
//! state, only fail to give one. PRIVACY: the wallet asks its OWN node for the contract it reads (as `/contract_leaves_from`
//! readers do); nothing about the person leaves the device. SCALE: one request; the state is at most `W(h)` slots.

use usdm_decider::dsol_blob_air as blob;
use usdm_decider::dsol_vm::{StorageTrie, VmVal};
use usdm_decider::poseidon2_compress::{hash32_to_digest, Digest};

fn hex32(s: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(s.trim()).ok()?.as_slice()).ok()
}

/// The trie a decrypted whole-state blob holds, with each string's bytes.
fn trie_of(writes: Vec<blob::Write>) -> Option<StorageTrie> {
    let mut t = StorageTrie::default();
    for w in writes {
        t.insert_checked(&w.key, w.val).ok()?;
        if let VmVal::Str { digest, .. } = w.val {
            t.contents.insert(digest, w.bytes);
        }
    }
    Some(t)
}

/// OPEN a call's record with `k_c`: the contract's state after that call, or `None` when the blob does not decrypt to
/// slots that fold to the record's post-state root.
#[must_use]
pub fn open_record(k_c: &Digest, tx_hash: &[u8; 32], salt: &[u8; 32], post: &Digest, b: &[u8]) -> Option<StorageTrie> {
    let writes = blob::decrypt_blob(k_c, &usdm_decider::dsol_vm::str_digest(tx_hash), &hash32_to_digest(salt), b)?;
    let t = trie_of(writes)?;
    (t.root() == *post).then_some(t)
}

/// The domain a snapshot's keystream is drawn under (never a call's: a call's tx hash is a nullifier's hash).
fn snapshot_tx(root: &Digest) -> Digest {
    let mut b = b"MonerousD/dsol/snapshot/v1".to_vec();
    b.extend_from_slice(&usdm_decider::poseidon2_compress::digest_to_bytes(root));
    usdm_decider::dsol_vm::str_digest(&b)
}

/// SEAL a state as a snapshot for the back end's site: `root ‖ salt ‖ count (u32 LE) ‖ blob`, every slot a write from
/// the empty trie, under `k_c` with a fresh salt. Only a holder of `k_c` reads it, and a reader accepts it only when its
/// slots fold to the root the chain's contract leaf holds.
#[must_use]
pub fn snapshot_seal(state: &StorageTrie, k_c: &Digest, salt: [u8; 32]) -> Option<Vec<u8>> {
    let writes = blob::writes_between(&StorageTrie::default(), state);
    let root = state.root();
    let (b, _) = blob::encrypt_blob(k_c, &snapshot_tx(&root), &hash32_to_digest(&salt), &writes, writes.len())?;
    let mut out = usdm_decider::poseidon2_compress::digest_to_bytes(&root).to_vec();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&u32::try_from(writes.len()).ok()?.to_le_bytes());
    out.extend_from_slice(&b);
    Some(out)
}

/// OPEN a snapshot with `k_c`: the trie, or `None` when it does not decrypt or its slots do not fold to its root.
#[must_use]
pub fn snapshot_open(bytes: &[u8], k_c: &Digest) -> Option<StorageTrie> {
    let root = usdm_decider::poseidon2_compress::digest_from_bytes(bytes.get(..32)?.try_into().ok()?)?;
    let salt: [u8; 32] = bytes.get(32..64)?.try_into().ok()?;
    let n = u32::from_le_bytes(bytes.get(64..68)?.try_into().ok()?) as usize;
    let b = bytes.get(68..)?;
    if b.len() != n * blob::ENTRY_BYTES {
        return None;
    }
    let t = trie_of(blob::decrypt_blob(k_c, &snapshot_tx(&root), &hash32_to_digest(&salt), b)?)?;
    (t.root() == root).then_some(t)
}

/// ⭐ THE CONTRACT'S STORAGE NOW: the trie whose root the chain's leaf for `cid` holds under `manifest`. `snapshot` is the
/// back end's sealed site snapshot, read when the node holds no record. `Err` names what is missing.
pub fn current(
    agent: &ureq::Agent,
    cid: &[u8; 32],
    k_c: &[u8; 32],
    manifest: &usdmd_node::dsol_deploy_tx::ContractManifest,
    chain_leaf: usdmd_node::spend_frontier::Digest4,
    snapshot: Option<&[u8]>,
) -> Result<StorageTrie, String> {
    let kd = hash32_to_digest(k_c);
    let is_now = |t: &StorageTrie| manifest.leaf(t.root()) == chain_leaf;
    let empty = StorageTrie::default();
    if is_now(&empty) {
        return Ok(empty); // deployed, never called
    }
    let v: serde_json::Value = agent
        .post(&format!("{}/contract_state_blob", crate::node_url()))
        .send_json(serde_json::json!({ "cid": hex::encode(cid) }))
        .map_err(|e| format!("the node did not serve the back end's storage: {e}"))?
        .into_json()
        .map_err(|e| format!("the back end's storage answer is unreadable: {e}"))?;
    // the node keeps a contract's last few records, newest first (a rewound fold step can leave an orphan on top): the
    // state is the newest one that opens to the root the chain's leaf holds now. Bounded by the node's KEEP (8).
    let kept = v["records"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut opened_any = false;
    for rec in kept.iter().take(usdmd_node::contract_blobs::KEEP) {
        let d = |k: &str| rec[k].as_str().and_then(hex32);
        let post = d("post").and_then(|b| usdmd_node::spend_frontier::cm_bytes_to_root(&b));
        let b = rec["blob"].as_str().and_then(|h| hex::decode(h).ok());
        let (Some(tx), Some(salt), Some(post), Some(b)) = (d("tx_hash"), d("salt"), post, b) else { continue };
        if let Some(t) = open_record(&kd, &tx, &salt, &post, &b) {
            opened_any = true;
            if is_now(&t) {
                return Ok(t);
            }
        }
    }
    if !kept.is_empty() && !opened_any {
        return Err("this back end's storage did not open with the site's key — the site gave a wrong key".into());
    }
    if let Some(t) = snapshot.and_then(|b| snapshot_open(b, &kd)).filter(is_now) {
        return Ok(t);
    }
    Err("this back end's newest state has not reached this wallet's node yet — try again in a few seconds".into())
}

// TWO-PARTY-REVIEWED: these check the reader's own opening of a record and a snapshot (one side). The two sides, a caller's
// wallet whose call another node's reader opens, are the real-node check scratchpad/net/backend.py.
#[cfg(test)]
mod tests {
    use super::*;
    use usdm_decider::dsol_blob_air::Write;
    use usdm_decider::poseidon2_compress::lanes_of;

    fn key(n: u64) -> Digest {
        lanes_of(&[0x6b65_79, n, n * 3 + 1])
    }
    fn state(texts: &[(u64, &[u8])]) -> StorageTrie {
        let mut t = StorageTrie::default();
        for (k, b) in texts {
            let d = usdm_decider::dsol_vm::str_digest(b);
            t.insert_checked(&key(*k), VmVal::Str { digest: d, len: b.len() as u32 }).unwrap();
            t.contents.insert(d, b.to_vec());
        }
        t.insert_checked(&key(99), VmVal::Word(7)).unwrap();
        t
    }

    #[test]
    fn a_reader_opens_a_whole_state_record_and_a_snapshot_only_with_the_key_and_only_at_their_root() {
        let k = hash32_to_digest(&[7; 32]);
        let s = state(&[(1, b"first post"), (2, b"a reply to it")]);
        let writes: Vec<Write> = blob::writes_between(&StorageTrie::default(), &s);
        let (tx, salt) = ([1u8; 32], [2u8; 32]);
        let (b, _) = blob::encrypt_blob(&k, &usdm_decider::dsol_vm::str_digest(&tx), &hash32_to_digest(&salt), &writes, 4).unwrap();
        let opened = open_record(&k, &tx, &salt, &s.root(), &b).expect("the record opens");
        assert_eq!(opened, s, "every slot and every text came back");
        assert!(open_record(&hash32_to_digest(&[8; 32]), &tx, &salt, &s.root(), &b).is_none(), "another key opened it");
        assert!(open_record(&k, &tx, &salt, &state(&[(1, b"first post")]).root(), &b).is_none(), "it opened at another root");
        let snap = snapshot_seal(&s, &k, [9; 32]).unwrap();
        assert_eq!(snapshot_open(&snap, &k), Some(s));
        assert!(snapshot_open(&snap, &hash32_to_digest(&[8; 32])).is_none());
        let mut torn = snap.clone();
        let at = torn.len() - 5;
        torn[at] ^= 1;
        assert!(snapshot_open(&torn, &k).is_none(), "a changed snapshot opened");
    }
}
