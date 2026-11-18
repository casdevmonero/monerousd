// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, The MoneroUSD Protocol. See LICENSE and NOTICE at the repository root.
pragma solidity 0.8.26;

// The vault's tamper tests (Foundry). RUN 2026-11-13 (forge, solc 0.8.26): 12 passed, 0 failed, with Vectors.t.sol 13 of 13.
// Each attack below must REVERT; each has a calibration beside it (the honest call passes), so a revert is the
// attack's and not the fixture's. Run with `forge test --offline` from contracts/eth.

import {IonVault, Forwarder} from "../src/IonVault.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function deal(address who, uint256 balance) external;
    function expectRevert(bytes calldata message) external;
    function prank(address sender) external;
    function chainId(uint256 id) external;
    function txGasPrice(uint256 price) external;
}

/// A recipient that refuses plain ether, to show a payout that cannot be delivered is set aside, not lost.
contract Refuser {
    bool public open;

    function setOpen(bool o) external {
        open = o;
    }

    function take(IonVault vault) external {
        vault.collect();
    }

    receive() external payable {
        require(open, "closed");
    }
}

contract IonVaultTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 private constant PAY_DOMAIN = keccak256("MoneroUSD IonVault pay v1");
    bytes32 private constant ROTATE_DOMAIN = keccak256("MoneroUSD IonVault rotate v1");

    IonVault private vault;
    uint256[] private keys; // the custodians' keys, in the order of their ascending addresses
    IonVault.SignerSet private set;

    function setUp() public {
        // three custodians, weights 5, 3, 2 (total 10), threshold 7: any two that include the heaviest, never the two light ones
        uint256[3] memory raw = [uint256(0xA11CE), uint256(0xB0B), uint256(0xCA11)];
        address[3] memory who = [vm.addr(raw[0]), vm.addr(raw[1]), vm.addr(raw[2])];
        // sort the three by address, ascending, keeping each key beside its address
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (who[j] < who[i]) {
                    (who[i], who[j]) = (who[j], who[i]);
                    (raw[i], raw[j]) = (raw[j], raw[i]);
                }
            }
        }
        delete keys;
        address[] memory signers = new address[](3);
        uint256[] memory weights = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys.push(raw[i]);
            signers[i] = who[i];
        }
        (weights[0], weights[1], weights[2]) = (5, 3, 2);
        set = IonVault.SignerSet({signers: signers, weights: weights, threshold: 7});
        vault = new IonVault(set);
        vm.deal(address(vault), 100 ether);
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────

    function payDigest(IonVault.Payout[] memory payouts, bytes32[] memory tags, uint256 refundCap, uint64 epoch, address at, uint256 chain)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(PAY_DOMAIN, chain, at, epoch, keccak256(abi.encode(payouts)), keccak256(abi.encode(tags)), refundCap));
    }

    function sigsOf(bytes32 digest, uint256[] memory places) private returns (IonVault.Sig[] memory out) {
        out = new IonVault.Sig[](places.length);
        for (uint256 i = 0; i < places.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[places[i]], digest);
            out[i] = IonVault.Sig({index: places[i], v: v, r: r, s: s});
        }
    }

    function one(bytes32 id, address to, uint256 amount) private pure returns (IonVault.Payout[] memory p) {
        p = new IonVault.Payout[](1);
        p[0] = IonVault.Payout({id: id, to: payable(to), amount: amount});
    }

    function places(uint256 a, uint256 b) private pure returns (uint256[] memory p) {
        p = new uint256[](2);
        (p[0], p[1]) = (a, b);
    }

    function noTags() private pure returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    // ── the honest path (the calibration every attack below leans on) ────────────────────────────────────────────────

    function test_a_quorum_of_bond_pays_and_the_recipient_holds_the_ether() public {
        address to = address(0xBEEF);
        IonVault.Payout[] memory p = one(keccak256("burn-1"), to, 1 ether);
        bytes32 d = payDigest(p, noTags(), 0, 0, address(vault), block.chainid);
        vault.pay(p, noTags(), 0, set, sigsOf(d, places(0, 1))); // weights 5 + 3 = 8 >= 7
        require(to.balance == 1 ether, "the recipient was not paid");
        require(vault.paid(keccak256("burn-1")), "the id was not recorded");
    }

    // ── attacks: each must revert ────────────────────────────────────────────────────────────────────────────────────

    function test_a_minority_of_bond_cannot_pay() public {
        IonVault.Payout[] memory p = one(keccak256("burn-2"), address(0xBEEF), 1 ether);
        bytes32 d = payDigest(p, noTags(), 0, 0, address(vault), block.chainid);
        IonVault.Sig[] memory light = sigsOf(d, places(1, 2)); // weights 3 + 2 = 5 < 7
        vm.expectRevert("below threshold");
        vault.pay(p, noTags(), 0, set, light);
    }

    function test_one_signer_counted_twice_is_refused() public {
        IonVault.Payout[] memory p = one(keccak256("burn-3"), address(0xBEEF), 1 ether);
        bytes32 d = payDigest(p, noTags(), 0, 0, address(vault), block.chainid);
        IonVault.Sig[] memory twice = sigsOf(d, places(0, 0)); // the heaviest signer twice would be 10 >= 7
        vm.expectRevert("signers out of order");
        vault.pay(p, noTags(), 0, set, twice);
    }

    function test_a_paid_id_is_never_paid_again() public {
        IonVault.Payout[] memory p = one(keccak256("burn-4"), address(0xBEEF), 1 ether);
        bytes32 d = payDigest(p, noTags(), 0, 0, address(vault), block.chainid);
        IonVault.Sig[] memory g = sigsOf(d, places(0, 1));
        vault.pay(p, noTags(), 0, set, g);
        vm.expectRevert("already paid");
        vault.pay(p, noTags(), 0, set, g); // the very same signed batch, sent again
    }

    function test_a_signature_for_another_amount_or_recipient_is_refused() public {
        IonVault.Payout[] memory signed = one(keccak256("burn-5"), address(0xBEEF), 1 ether);
        bytes32 d = payDigest(signed, noTags(), 0, 0, address(vault), block.chainid);
        IonVault.Sig[] memory g = sigsOf(d, places(0, 1));
        vm.expectRevert("bad signature");
        vault.pay(one(keccak256("burn-5"), address(0xBEEF), 50 ether), noTags(), 0, set, g); // the amount raised
        vm.expectRevert("bad signature");
        vault.pay(one(keccak256("burn-5"), address(0xDEAD), 1 ether), noTags(), 0, set, g); // the recipient changed
    }

    function test_a_signature_for_another_chain_or_another_vault_is_refused() public {
        IonVault.Payout[] memory p = one(keccak256("burn-6"), address(0xBEEF), 1 ether);
        IonVault.Sig[] memory otherChain = sigsOf(payDigest(p, noTags(), 0, 0, address(vault), block.chainid + 1), places(0, 1));
        vm.expectRevert("bad signature");
        vault.pay(p, noTags(), 0, set, otherChain);
        IonVault twin = new IonVault(set);
        IonVault.Sig[] memory otherVault = sigsOf(payDigest(p, noTags(), 0, 0, address(twin), block.chainid), places(0, 1));
        vm.expectRevert("bad signature");
        vault.pay(p, noTags(), 0, set, otherVault);
    }

    function test_a_set_that_is_not_the_current_one_is_refused() public {
        IonVault.Payout[] memory p = one(keccak256("burn-7"), address(0xBEEF), 1 ether);
        bytes32 d = payDigest(p, noTags(), 0, 0, address(vault), block.chainid);
        IonVault.Sig[] memory g = sigsOf(d, places(0, 1));
        IonVault.SignerSet memory forged = set;
        forged.threshold = 6; // the same signers, an easier threshold
        vm.expectRevert("not the current set");
        vault.pay(p, noTags(), 0, forged, g);
    }

    function test_after_a_hand_over_the_old_sets_signatures_stop_counting() public {
        // the next set: one signer of its own
        uint256 nextKey = 0xD00D;
        address[] memory s2 = new address[](1);
        uint256[] memory w2 = new uint256[](1);
        (s2[0], w2[0]) = (vm.addr(nextKey), 1);
        IonVault.SignerSet memory next = IonVault.SignerSet({signers: s2, weights: w2, threshold: 1});
        bytes32 nextHash = keccak256(abi.encode(next.signers, next.weights, next.threshold, uint64(1)));
        bytes32 rd = keccak256(abi.encode(ROTATE_DOMAIN, block.chainid, address(vault), uint64(0), nextHash));
        // a payout the OLD set signed before the hand-over
        IonVault.Payout[] memory p = one(keccak256("burn-8"), address(0xBEEF), 1 ether);
        IonVault.Sig[] memory old = sigsOf(payDigest(p, noTags(), 0, 0, address(vault), block.chainid), places(0, 1));
        // a minority cannot hand the vault over
        IonVault.Sig[] memory lightRotate = sigsOf(rd, places(1, 2));
        vm.expectRevert("below threshold");
        vault.rotate(next, set, lightRotate);
        // the quorum does
        vault.rotate(next, set, sigsOf(rd, places(0, 1)));
        require(vault.epoch() == 1, "the epoch did not advance");
        // the old set's payout no longer passes, under the old set or the new
        vm.expectRevert("not the current set");
        vault.pay(p, noTags(), 0, set, old);
    }

    function test_a_set_a_minority_could_control_is_refused_at_creation() public {
        address[] memory s = new address[](2);
        uint256[] memory w = new uint256[](2);
        (s[0], s[1]) = (address(0x1), address(0x2));
        (w[0], w[1]) = (5, 5);
        vm.expectRevert("threshold");
        new IonVault(IonVault.SignerSet({signers: s, weights: w, threshold: 5})); // exactly half is not above half
        (s[0], s[1]) = (address(0x2), address(0x1));
        vm.expectRevert("signers not ascending");
        new IonVault(IonVault.SignerSet({signers: s, weights: w, threshold: 6}));
    }

    // ── a recipient that cannot be paid, deposits, and the caller's refund ───────────────────────────────────────────

    function test_a_recipient_that_refuses_ether_is_set_aside_and_the_batch_goes_on() public {
        Refuser stuck = new Refuser();
        IonVault.Payout[] memory p = new IonVault.Payout[](2);
        p[0] = IonVault.Payout({id: keccak256("burn-9a"), to: payable(address(stuck)), amount: 2 ether});
        p[1] = IonVault.Payout({id: keccak256("burn-9b"), to: payable(address(0xBEEF)), amount: 1 ether});
        bytes32 d = payDigest(p, noTags(), 0, 0, address(vault), block.chainid);
        vault.pay(p, noTags(), 0, set, sigsOf(d, places(0, 1)));
        require(address(0xBEEF).balance == 1 ether, "the second payout did not go out");
        require(vault.owed(address(stuck)) == 2 ether && vault.owedTotal() == 2 ether, "the first was not set aside");
        // the ether set aside is not anyone else's to spend: a payout of everything else passes, one wei more does not
        uint256 free = address(vault).balance - 2 ether;
        IonVault.Payout[] memory tooMuch = one(keccak256("burn-9c"), address(0xBEEF), free + 1);
        IonVault.Sig[] memory g = sigsOf(payDigest(tooMuch, noTags(), 0, 0, address(vault), block.chainid), places(0, 1));
        vm.expectRevert("vault short");
        vault.pay(tooMuch, noTags(), 0, set, g);
        // the recipient opens and collects what is its own, once
        stuck.setOpen(true);
        stuck.take(vault);
        require(address(stuck).balance == 2 ether && vault.owedTotal() == 0, "the set-aside ether was not collected");
        vm.expectRevert("nothing owed");
        stuck.take(vault);
    }

    function test_a_plain_transfer_to_a_one_time_address_is_swept_into_the_vault() public {
        bytes32 tag = keccak256("deposit-1");
        address at = vault.depositAddress(tag);
        vm.deal(at, 3 ether); // a depositor's plain transfer
        uint256 before = address(vault).balance;
        bytes32[] memory tags = new bytes32[](2);
        (tags[0], tags[1]) = (tag, keccak256("deposit-nobody-sent")); // an empty address is skipped
        vault.sweep(tags);
        require(address(vault).balance == before + 3 ether && at.balance == 0, "the deposit did not reach the vault");
        vault.sweep(tags); // a second sweep finds nothing and moves nothing
        require(address(vault).balance == before + 3 ether, "a swept deposit moved twice");
        // two tags never share an address
        require(vault.depositAddress(keccak256("deposit-2")) != at, "two deposits share an address");
    }

    function test_the_callers_refund_never_exceeds_the_signed_cap() public {
        address caller = address(0xC0FFEE);
        IonVault.Payout[] memory p = one(keccak256("burn-10"), address(0xBEEF), 1 ether);
        uint256 cap = 1000 gwei;
        bytes32 d = payDigest(p, noTags(), cap, 0, address(vault), block.chainid);
        IonVault.Sig[] memory g = sigsOf(d, places(0, 1));
        vm.txGasPrice(1_000_000 gwei); // an absurd gas price: the measured cost is far above the cap
        vm.prank(caller);
        vault.pay(p, noTags(), cap, set, g);
        require(caller.balance == cap, "the refund is not the signed cap");
        // and the cap itself is signed: the same signatures do not pass under a higher cap
        IonVault.Payout[] memory q = one(keccak256("burn-11"), address(0xBEEF), 1 ether);
        IonVault.Sig[] memory h = sigsOf(payDigest(q, noTags(), cap, 0, address(vault), block.chainid), places(0, 1));
        vm.expectRevert("bad signature");
        vault.pay(q, noTags(), cap * 100, set, h);
    }
}
