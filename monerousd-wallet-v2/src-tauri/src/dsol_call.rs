// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐ DSOL ITEM 2 — THE WALLET'S CALL BUILDER (docs/DSOL-NODE-DOOR-SPEC.md §1, §6b A1–A3, §9).
//!
//! A DSOL call is PROVEN by the wallet and VERIFIED by the node's door, which never re-executes it. The door can only
//! compare the statement against values it re-derives from PUBLIC bytes the call carries, so every context value the
//! machine lands must be a public function of those bytes. The wallet computes each one through the SAME function
//! the door calls, never a local spelling:
//!
//! | statement field | the value | re-derived by the door from |
//! |---|---|---|
//! | `caller` (`MSG_SENDER`) | `dsol_caller_wallet(pk_c)` | the carried caller key `pk_c` (A1) |
//! | `subaddress` (`MSG_SUBADDRESS`) | `dsol_caller_subaddress(pk_c)` | the same key (A1) |
//! | `tx_hash` (`TX_HASH`) | `dsol_tx_hash(fee_nf)` | the carried fee spend's nullifier (A2) |
//! | `block_number` (`BLOCK_NUMBER`) | `dsol_block_number(carrying_blue)` | the carrying block's blue score (A3) |
//! | `cid` | `str_digest(contract_id)` | the object's contract id |
//!
//! `pk_c` is the per-`(seed, cid, index)` ML-DSA-65 key from [`crate::pq::derive_dsol_caller`], so a contract sees a
//! contract-scoped pseudonym and a fresh `index` per call unlinks calls within one contract.
//!
//! PRIVACY — THE HEIGHT CLASS IS NEVER THE RUN'S OWN. A proof's table height is public. At the natural height it would
//! tell a viewer which size class of execution ran (branches, loop counts). So the builder REQUIRES the contract's
//! height class and pads every call to it (`prove_dsol_call_run` with `Some(h)`). There is no natural-height default.
//! A class below the run's own is REFUSED, never raised silently, so a call can only take the shape every call of its
//! contract has.
//!
//! What this module does NOT do yet, named: sign the object. The signature covers the node's `DsolCallTx` body minus
//! the signature, and that encoding lands with the door (spec §9 order, step 5). `pq::sign_dsol_call` signs it then.
//! Until the door lands, no DSOL call can be admitted anywhere, so nothing here reaches the wire.

use usdm_decider::dsol_cpu_air::{self, DsolCallProof, DsolStatement};
use usdm_decider::dsol_vm::{self, StorageTrie, SyscallHost, VmCtx, VmRun};

/// The context a call runs under, from the carried caller key, the contract, the fee spend's nullifier and the blue
/// score of the block the wallet expects to carry it. `None` when `pk_c` is not an ML-DSA-65 key: a key that cannot
/// verify the call's signature names no caller.
#[must_use]
pub fn call_ctx(pk_c: &[u8], contract_id: &[u8; 32], fee_nf: &[u8; 32], carrying_blue: u64) -> Option<VmCtx> {
    Some(VmCtx {
        contract_id: *contract_id,
        block_number: usdmd_node::dsol::dsol_block_number(carrying_blue),
        tx_hash: dsol_vm::dsol_tx_hash(fee_nf),
        caller_wallet: dsol_vm::dsol_caller_wallet(pk_c)?,
        caller_subaddress: dsol_vm::dsol_caller_subaddress(pk_c)?,
    })
}

/// A proven call, ready for the door's object: the caller key the object carries, the statement and proof, and the
/// machine's run (its effects and the prover-side storage the post-write blob is sealed from, spec D4).
pub struct BuiltCall {
    pub pk_c: Vec<u8>,
    pub stmt: DsolStatement,
    pub proof: DsolCallProof,
    pub run: VmRun,
}

/// What one call is: the contract, the caller index under it, the code the object carries, the entrypoint and its
/// arguments, the storage the call starts from, and the contract's height class.
pub struct CallRequest<'a> {
    pub contract_id: [u8; 32],
    pub index: u32,
    pub code: &'a [u8],
    pub entrypoint: &'a str,
    pub argv: &'a [u8],
    pub storage: StorageTrie,
    pub height_log2: u8,
}

/// Prove a DSOL call as `dsol_root`'s `index`-th caller of `req.contract_id`, paying from the note whose nullifier is
/// `fee_nf`, for the block the wallet expects at `carrying_blue`. `None` on any refusal: a caller key that does not
/// derive, a machine refusal, a step budget above the protocol's, or a height class the run does not fit.
#[must_use]
pub fn build_call<H: SyscallHost>(
    dsol_root: &[u8; 32],
    req: CallRequest<'_>,
    fee_nf: &[u8; 32],
    carrying_blue: u64,
    budget: u64,
    host: &mut H,
) -> Option<BuiltCall> {
    if budget > dsol_vm::STEP_BUDGET_MAX {
        return None;
    }
    let caller = crate::pq::derive_dsol_caller(dsol_root, &req.contract_id, req.index);
    let ctx = call_ctx(&caller.pk, &req.contract_id, fee_nf, carrying_blue)?;
    let (proof, stmt, run) = dsol_cpu_air::prove_dsol_call_run(
        req.code,
        req.entrypoint,
        req.argv,
        ctx,
        req.storage,
        budget,
        host,
        Some(req.height_log2),
    )?;
    Some(BuiltCall { pk_c: caller.pk, stmt, proof, run })
}

#[cfg(test)]
mod tests {
    use super::*;
    use usdm_decider::dsol_vm::op;

    /// `main`: drop the argument, push `MSG_SENDER`, return it. The call returns the caller identity the machine saw,
    /// so the pin can check it against the door's re-derivation, not merely against the statement.
    fn sender_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        out.push(op::MSG_SENDER);
        out.push(op::RETURN);
        out
    }

    fn request(code: &[u8], index: u32, height_log2: u8) -> CallRequest<'_> {
        CallRequest {
            contract_id: [0xC1; 32],
            index,
            code,
            entrypoint: "main",
            argv: b"",
            storage: StorageTrie::default(),
            height_log2,
        }
    }

    /// ⭐ DSOL item 2 — A WALLET CALL IS PROVEN UNDER EXACTLY THE CONTEXT THE DOOR RE-DERIVES, and a statement that
    /// names any other context does not verify.
    ///
    /// The honest arm checks every context field of the statement against the door's own public function of the carried
    /// bytes (`pk_c`, `fee_nf`, the carrying blue score), plus the contract's view: the call RETURNED
    /// `dsol_caller_wallet(pk_c)`.
    ///
    /// The tamper arms REJECT:
    /// - another index's caller, another fee's `tx_hash`, and the next epoch's `block_number` each fail
    ///   `verify_dsol_call` against the honest proof;
    /// - the door's comparison refuses index 0's statement under index 1's key;
    /// - a height class below the run's own is refused at build time, never raised.
    ///
    /// TWO-PARTY-REVIEWED: this is the wallet half (key, context, proof). The node half, the door's re-derivation and
    /// verify on two nodes, is the door's pin (`dsol_a_forged_caller_is_refused…`, spec §6), which lands with the door.
    #[test]
    fn dsol_item2_a_call_is_proven_under_the_context_the_door_rederives_and_no_other() {
        let keys = crate::pq::derive_keys(&[0x5Du8; 32]);
        let code = sender_program();
        let fee_nf = [0xFE; 32];
        let blue = 1_000u64;
        let h = 6u8;
        let built = build_call(&keys.dsol_root, request(&code, 0, h), &fee_nf, blue, 1 << 16, &mut dsol_vm::NoHost)
            .expect("the honest call proves");
        assert!(dsol_cpu_air::verify_dsol_call(&built.proof, &code, &built.stmt), "the honest call verifies");

        // every context field is the door's own re-derivation from the carried public bytes
        assert_eq!(Some(built.stmt.caller), dsol_vm::dsol_caller_digest(&built.pk_c), "caller = f(pk_c)");
        assert_eq!(Some(built.stmt.subaddress), dsol_vm::dsol_caller_subaddress_digest(&built.pk_c), "subaddress = f(pk_c)");
        assert_eq!(built.stmt.tx_hash, dsol_vm::str_digest(&dsol_vm::dsol_tx_hash(&fee_nf)), "tx_hash = f(fee_nf)");
        assert_eq!(built.stmt.block_number, usdmd_node::dsol::dsol_block_number(blue), "block_number = f(carrying blue)");
        assert_eq!(built.stmt.block_number, 960, "the epoch floor of 1,000 at 64-block epochs");
        assert_eq!(built.stmt.cid, dsol_vm::str_digest(&[0xC1; 32]), "cid = the object's contract id");
        assert_eq!(built.stmt.height_log2, h, "the call takes its contract's height class, not the run's own");
        assert_eq!(
            Some(built.run.ret.clone()),
            dsol_vm::dsol_caller_wallet(&built.pk_c).map(|w| w.to_vec()),
            "the contract saw the door's caller"
        );

        // TAMPER — another caller (index 1 of the same contract) named in the honest proof's statement
        let other = crate::pq::derive_dsol_caller(&keys.dsol_root, &[0xC1; 32], 1);
        let mut forged = built.stmt.clone();
        forged.caller = dsol_vm::dsol_caller_digest(&other.pk).expect("an ML-DSA-65 key");
        assert!(!dsol_cpu_air::verify_dsol_call(&built.proof, &code, &forged), "⛔ a proof verified under another caller");
        // …and the door's own comparison refuses the honest statement under the other key
        assert_ne!(Some(built.stmt.caller), dsol_vm::dsol_caller_digest(&other.pk), "⛔ two indices name one caller");

        // TAMPER — another fee spend's tx_hash
        let mut forged = built.stmt.clone();
        forged.tx_hash = dsol_vm::str_digest(&dsol_vm::dsol_tx_hash(&[0xEF; 32]));
        assert!(!dsol_cpu_air::verify_dsol_call(&built.proof, &code, &forged), "⛔ a proof verified under another fee's tx_hash");

        // TAMPER — the next epoch: a call proven for one epoch cannot ride a block of the next
        let mut forged = built.stmt.clone();
        forged.block_number = usdmd_node::dsol::dsol_block_number(blue + usdmd_node::oli::EPOCH_BLOCKS);
        assert_ne!(forged.block_number, built.stmt.block_number, "the next epoch is a different BLOCK_NUMBER");
        assert!(!dsol_cpu_air::verify_dsol_call(&built.proof, &code, &forged), "⛔ a proof verified in another epoch");

        // HEIGHT — a class below the run's own is refused, never silently raised to the natural class
        assert!(
            build_call(&keys.dsol_root, request(&code, 0, 4), &fee_nf, blue, 1 << 16, &mut dsol_vm::NoHost).is_none(),
            "⛔ a call was built at a height class below the smallest table"
        );
        // BUDGET — above the protocol's step budget is refused before any work
        assert!(
            build_call(&keys.dsol_root, request(&code, 0, h), &fee_nf, blue, dsol_vm::STEP_BUDGET_MAX + 1, &mut dsol_vm::NoHost)
                .is_none(),
            "⛔ a call was built above the protocol's step budget"
        );
    }

    /// The epoch floor is exact at both edges, so a call proven for one epoch never matches a block in the next.
    #[test]
    fn dsol_item2_block_number_is_the_carrying_epochs_floor_at_both_edges() {
        let e = usdmd_node::oli::EPOCH_BLOCKS;
        assert_eq!(usdmd_node::dsol::dsol_block_number(0), 0);
        assert_eq!(usdmd_node::dsol::dsol_block_number(e - 1), 0, "the last block of epoch 0");
        assert_eq!(usdmd_node::dsol::dsol_block_number(e), e, "the first block of epoch 1");
        assert_eq!(usdmd_node::dsol::dsol_block_number(2 * e - 1), e);
        assert_ne!(
            usdmd_node::dsol::dsol_block_number(e - 1),
            usdmd_node::dsol::dsol_block_number(e),
            "⛔ two epochs share a BLOCK_NUMBER"
        );
    }
}
