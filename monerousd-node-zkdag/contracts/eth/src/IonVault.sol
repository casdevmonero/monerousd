// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, The MoneroUSD Protocol. See LICENSE and NOTICE at the repository root.
pragma solidity 0.8.26;

// IonVault: the MoneroUSD bridge's vault on Ethereum (docs/BRIDGE-MORE-COINS-SPEC-20261110.md, section 3.1).
//
// STATUS: compiled with the pinned compiler and tested (test/IonVault.t.sol: every refusal; test/Vectors.t.sol: the
// values the node's mirror, src/eth_vault.rs, reproduces byte for byte). NOT DEPLOYED on any public network and NOT
// AUDITED by an outside party: both come before it holds anyone's ether.
//
// WHAT IT IS. The ether the bridge holds for MoneroUSD sits here. It leaves only when the CURRENT custody set signs:
// each custodian signs with its OWN key, a signature counts for that custodian's bond weight, and a call passes when
// the signed weight reaches the threshold (two thirds of bond, set by the chain). No key shares, no signing session:
// the Bitcoin vault's shape (one script, each custodian its own key), written as a contract because Ethereum has no
// script.
//
// WHAT IT IS NOT. There is no owner, no admin, no guardian, no pause, no upgrade proxy and no self-destruct. Nobody,
// including the people who wrote it, can freeze, redirect or recover funds. The only two calls that move ether out or
// change who may sign are `pay` and `rotate`, and both need the custody set's signed weight.
//
// REPLAY IS REFUSED BY A SET. Every payout carries an id the chain derives from the burn that owes it; the contract
// records each id it has paid and refuses it for ever after. A signature binds the chain id, this contract's address
// and the signer set's epoch, so it is useless on another chain, another vault or after a hand-over.
//
// A FAILED PAYOUT NEVER BLOCKS THE OTHERS AND NEVER LOSES MONEY. If a recipient cannot take ether (a contract that
// reverts), its amount is set aside under its address and it collects it itself with `collect`. The batch goes on.
//
// DEPOSITS. A depositor sends a plain transfer to a one-time address: the CREATE2 address of a `Forwarder` whose salt
// is the deposit's tag. Any node derives that address with no call (`depositAddress`). `sweep` deploys the forwarder,
// which hands its whole balance to this vault; anyone may call it, because it can only move ether INTO the vault.
// A wallet that can attach data may call `deposit(tag)` directly instead.
//
// BORROWED: Safe's `checkNSignatures` (recover each signer, strictly ascending, no duplicates); Axelar's weighted
// signer set kept as one hash and handed over by its own quorum; THORChain's router (a vault contract paying out on
// the custody set's word); OpenZeppelin's pull-payment pattern for a recipient that cannot be paid.
//
// CLASSICAL-CRYPTO-EXEMPT: Ethereum's own signature (recovered by its built-in precompile) is the only thing an
// Ethereum contract can check; this is the foreign chain's endpoint, never the MoneroUSD base layer.

/// The one-time deposit forwarder: created by the vault at a deposit's own address, it hands everything it holds to
/// the vault in its constructor and leaves no callable code behind.
contract Forwarder {
    constructor() payable {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "forward failed");
    }
}

contract IonVault {
    /// One payout: the id the chain derived from the burn that owes it, who is paid, and how much (wei).
    struct Payout {
        bytes32 id;
        address payable to;
        uint256 amount;
    }

    /// One custodian's signature: its place in the signer list and the signature's three parts.
    struct Sig {
        uint256 index;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// The custody set, passed with every call and checked against `signerSetHash` (so the vault stores one word).
    struct SignerSet {
        address[] signers; // strictly ascending, no zero address
        uint256[] weights; // one per signer, each above zero
        uint256 threshold; // the signed weight a call needs: above half of the total, at most the total
    }

    bytes32 private constant PAY_DOMAIN = keccak256("MoneroUSD IonVault pay v1");
    bytes32 private constant ROTATE_DOMAIN = keccak256("MoneroUSD IonVault rotate v1");
    // the upper half of the curve order: a signature above it has a twin below it, so only the lower is taken
    uint256 private constant HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    // gas a recipient is given to take its payout: enough for a plain account or a simple wallet, never a long call
    uint256 private constant PAYOUT_GAS = 30000;
    // gas charged per call on top of what is measured, for the part before the first and after the last measurement
    uint256 private constant REFUND_OVERHEAD_GAS = 50000;

    /// keccak256(abi.encode(signers, weights, threshold, epoch)) of the set that may sign now.
    bytes32 public signerSetHash;
    /// How many hand-overs there have been. Bound into every signature.
    uint64 public epoch;
    /// Payout ids already paid (or set aside). A second payout with the same id is refused.
    mapping(bytes32 => bool) public paid;
    /// Ether set aside for a recipient that could not take its payout; it collects it with `collect`.
    mapping(address => uint256) public owed;
    /// The total set aside, so a payout can never spend ether that is already someone's.
    uint256 public owedTotal;
    uint256 private locked = 1;

    event Paid(bytes32 indexed id, address indexed to, uint256 amount);
    event SetAside(bytes32 indexed id, address indexed to, uint256 amount);
    event Collected(address indexed to, uint256 amount);
    event Deposited(bytes32 indexed tag, uint256 amount);
    event Swept(bytes32 indexed tag, address from, uint256 amount);
    event Rotated(uint64 indexed epoch, bytes32 signerSetHash);

    modifier oneAtATime() {
        require(locked == 1, "busy");
        locked = 2;
        _;
        locked = 1;
    }

    constructor(SignerSet memory set) {
        _checkShape(set.signers, set.weights, set.threshold);
        signerSetHash = keccak256(abi.encode(set.signers, set.weights, set.threshold, uint64(0)));
        emit Rotated(0, signerSetHash);
    }

    /// Plain ether in: a forwarder's hand-over, or anyone adding to the vault. Nothing is credited to anybody by this.
    receive() external payable {}

    /// A deposit made by a direct call: the tag is the deposit's own (the chain mints against it).
    function deposit(bytes32 tag) external payable {
        require(msg.value > 0, "nothing sent");
        emit Deposited(tag, msg.value);
    }

    /// The one-time address a deposit with this tag is sent to. A pure function of this vault and the tag.
    function depositAddress(bytes32 tag) public view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), tag, keccak256(type(Forwarder).creationCode)));
        return address(uint160(uint256(h)));
    }

    /// Bring the ether waiting at one-time deposit addresses into the vault. Anyone may call it: it can only move
    /// ether in. A tag with nothing waiting, or one already swept, is skipped.
    function sweep(bytes32[] calldata tags) external oneAtATime {
        _sweep(tags);
    }

    /// Pay a batch the custody set signed. `refundCap` is the most wei the caller may be repaid for this call's gas;
    /// it is part of what the set signed, so a caller cannot pay itself more.
    function pay(
        Payout[] calldata payouts,
        bytes32[] calldata sweepTags,
        uint256 refundCap,
        SignerSet calldata set,
        Sig[] calldata sigs
    ) external oneAtATime {
        uint256 startGas = gasleft();
        bytes32 digest = keccak256(
            abi.encode(PAY_DOMAIN, block.chainid, address(this), epoch, keccak256(abi.encode(payouts)), keccak256(abi.encode(sweepTags)), refundCap)
        );
        _checkSigned(digest, set, sigs);
        _sweep(sweepTags);
        for (uint256 i = 0; i < payouts.length; i++) {
            Payout calldata p = payouts[i];
            require(!paid[p.id], "already paid");
            require(p.to != address(0) && p.amount > 0, "empty payout");
            // ether already set aside for someone is not this payout's to spend
            require(address(this).balance - owedTotal >= p.amount, "vault short");
            paid[p.id] = true;
            (bool ok, ) = p.to.call{value: p.amount, gas: PAYOUT_GAS}("");
            if (ok) {
                emit Paid(p.id, p.to, p.amount);
            } else {
                owed[p.to] += p.amount;
                owedTotal += p.amount;
                emit SetAside(p.id, p.to, p.amount);
            }
        }
        // the caller's gas, repaid from the vault inside the signed cap (never more than what is free of set-aside ether)
        uint256 refund = (startGas - gasleft() + REFUND_OVERHEAD_GAS) * tx.gasprice;
        if (refund > refundCap) refund = refundCap;
        uint256 free = address(this).balance - owedTotal;
        if (refund > free) refund = free;
        if (refund > 0) {
            (bool sent, ) = payable(msg.sender).call{value: refund}("");
            require(sent, "refund failed");
        }
    }

    /// A recipient that could not be paid takes what was set aside for it.
    function collect() external oneAtATime {
        uint256 amount = owed[msg.sender];
        require(amount > 0, "nothing owed");
        owed[msg.sender] = 0;
        owedTotal -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "collect failed");
        emit Collected(msg.sender, amount);
    }

    /// Hand the vault to the next custody set. Signed by the current set; every signature made before it stops counting.
    function rotate(SignerSet calldata next, SignerSet calldata set, Sig[] calldata sigs) external oneAtATime {
        _checkShape(next.signers, next.weights, next.threshold);
        uint64 nextEpoch = epoch + 1;
        bytes32 nextHash = keccak256(abi.encode(next.signers, next.weights, next.threshold, nextEpoch));
        bytes32 digest = keccak256(abi.encode(ROTATE_DOMAIN, block.chainid, address(this), epoch, nextHash));
        _checkSigned(digest, set, sigs);
        epoch = nextEpoch;
        signerSetHash = nextHash;
        emit Rotated(nextEpoch, nextHash);
    }

    function _sweep(bytes32[] calldata tags) private {
        for (uint256 i = 0; i < tags.length; i++) {
            address from = depositAddress(tags[i]);
            uint256 waiting = from.balance;
            if (waiting == 0 || from.code.length != 0) continue;
            new Forwarder{salt: tags[i]}();
            emit Swept(tags[i], from, waiting);
        }
    }

    /// The set passed in is the current one, and its signatures over `digest` reach the threshold.
    function _checkSigned(bytes32 digest, SignerSet calldata set, Sig[] calldata sigs) private view {
        require(keccak256(abi.encode(set.signers, set.weights, set.threshold, epoch)) == signerSetHash, "not the current set");
        uint256 weight = 0;
        uint256 last = type(uint256).max;
        for (uint256 i = 0; i < sigs.length; i++) {
            Sig calldata g = sigs[i];
            // strictly ascending places: no signer is counted twice
            require(g.index < set.signers.length && (last == type(uint256).max || g.index > last), "signers out of order");
            last = g.index;
            require(uint256(g.s) <= HALF_ORDER && (g.v == 27 || g.v == 28), "signature form");
            // CLASSICAL-CRYPTO-EXEMPT: Ethereum's own signature recovery, the foreign chain's only signature check
            address who = ecrecover(digest, g.v, g.r, g.s);
            require(who != address(0) && who == set.signers[g.index], "bad signature");
            weight += set.weights[g.index];
        }
        require(weight >= set.threshold, "below threshold");
    }

    /// A signer set is well formed: ascending distinct addresses, a positive weight each, and a threshold no minority
    /// can reach (above half of the total weight) and the whole set can (at most the total).
    function _checkShape(address[] memory signers, uint256[] memory weights, uint256 threshold) private pure {
        require(signers.length > 0 && signers.length == weights.length, "set shape");
        uint256 total = 0;
        address prev = address(0);
        for (uint256 i = 0; i < signers.length; i++) {
            require(signers[i] > prev, "signers not ascending");
            require(weights[i] > 0, "zero weight");
            prev = signers[i];
            total += weights[i];
        }
        require(threshold * 2 > total && threshold <= total, "threshold");
    }
}
