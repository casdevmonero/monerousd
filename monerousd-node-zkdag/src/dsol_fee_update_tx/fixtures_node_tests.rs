// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! `dsol_fee_update_tx::fixtures` — the tests of `dsol_fee_update_tx` that drive a `Node`, kept in the node crate by the node split (stage B, lane
//! dcash 2026-11-11): `dsol_fee_update_tx` itself compiles in the ledger crate, which never names the node. Moved byte for byte; the test
//! path is unchanged (`dsol_fee_update_tx::fixtures::…`), and `use super::*` reaches `dsol_fee_update_tx`'s items through the node's re-export.

// the imports of `dsol_fee_update_tx` itself (private to it, so its re-export does not carry them)
#[allow(unused_imports)]
use crate::contract_state::update_root;
#[allow(unused_imports)]
use crate::contract_state::PathWire;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ContractManifest;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::DSOL_PUBLISHER_FEE_MAX_ATOMIC;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES;
#[allow(unused_imports)]
use crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES;
#[allow(unused_imports)]
use crate::spend_frontier::Digest4;

use super::*;

/// A signed fee cut of the deployed contract `d` (current storage `storage_root`) to `new_fee`, built on `tree`.
pub(crate) fn cut(
    d: &crate::dsol_deploy_tx::DsolDeployTx,
    who: &crate::dsol_deploy_tx::fixtures::Deployer,
    tree: &crate::contract_state::ContractStateTree,
    storage_root: Digest4,
    new_fee: u64,
) -> DsolFeeUpdateTx {
    let mut t = DsolFeeUpdateTx {
        cid: d.cid(),
        manifest: d.manifest(),
        storage_root: crate::spend_frontier::leaf_to_cm_bytes(storage_root),
        state_path: tree.path(&d.cid()),
        new_fee_le: new_fee.to_le_bytes(),
        deployer_pk: who.pk.clone(),
        sig: Vec::new(),
    };
    t.sig = crate::pqauth::ml_dsa_sign(&t.signing_body(), &who.sk).expect("the deployer signs");
    t
}
