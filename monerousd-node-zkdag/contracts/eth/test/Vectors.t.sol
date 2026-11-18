// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026, The MoneroUSD Protocol. See LICENSE and NOTICE at the repository root.
pragma solidity 0.8.26;

// Vectors for the node's Rust mirror of this vault's arithmetic (monerousd-node-zkdag/src/eth_vault.rs): every value the
// node must compute byte for byte the way the contract does, printed from the contract's own code for fixed inputs.
// `forge test --match-contract VectorsTest -vv` prints them; the mirror's tests hold the printed values as constants, so
// a change to the contract that moves any of them fails the node's tests until both sides agree again.
// The three keys below are test values that exist only in this file.
import {IonVault, Forwarder} from "../src/IonVault.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function chainId(uint256 id) external;
}

contract VectorsTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_bytes32(string key, bytes32 val);
    event log_named_address(string key, address val);
    event log_named_bytes(string key, bytes val);
    event log_named_uint(string key, uint256 val);

    uint256[3] keys;
    address[3] who;
    IonVault vault;
    bytes32 tag;

    function currentSet() internal view returns (IonVault.SignerSet memory set) {
        set.signers = new address[](3);
        set.weights = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) set.signers[i] = who[i];
        set.weights[0] = 5; set.weights[1] = 3; set.weights[2] = 2;
        set.threshold = 7;
    }

    /// The first two custodians (weight 8 of 10) sign `digest`; each part is printed under `name`.
    function signTwo(bytes32 digest, string memory name) internal returns (IonVault.Sig[] memory sigs) {
        sigs = new IonVault.Sig[](2);
        for (uint256 i = 0; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            sigs[i] = IonVault.Sig(i, v, r, s);
            emit log_named_uint(string.concat(name, ".v"), v);
            emit log_named_bytes32(string.concat(name, ".r"), r);
            emit log_named_bytes32(string.concat(name, ".s"), s);
        }
    }

    function setUpVault() internal {
        vm.chainId(31337);
        keys = [uint256(0x1111111111111111111111111111111111111111111111111111111111111111), uint256(0x2222222222222222222222222222222222222222222222222222222222222222), uint256(0x3333333333333333333333333333333333333333333333333333333333333333)];
        for (uint256 i = 0; i < 3; i++) who[i] = vm.addr(keys[i]);
        // ascending order, as the contract demands
        for (uint256 i = 0; i < 3; i++) for (uint256 j = i + 1; j < 3; j++) if (who[j] < who[i]) { (who[i], who[j]) = (who[j], who[i]); (keys[i], keys[j]) = (keys[j], keys[i]); }
        for (uint256 i = 0; i < 3; i++) { emit log_named_address("signer", who[i]); emit log_named_bytes32("key", bytes32(keys[i])); }
        vault = new IonVault(currentSet());
        emit log_named_address("vault", address(vault));
        emit log_named_bytes32("signerSetHash", vault.signerSetHash());
        tag = keccak256("deposit tag one");
        emit log_named_bytes32("tag", tag);
        emit log_named_address("depositAddress", vault.depositAddress(tag));
        emit log_named_bytes32("forwarderCodeHash", keccak256(type(Forwarder).creationCode));
    }

    /// A payout batch of two, one waiting deposit swept in passing: printed, then taken by the contract.
    function payVectors() internal {
        IonVault.Payout[] memory pays = new IonVault.Payout[](2);
        pays[0] = IonVault.Payout(keccak256("burn one"), payable(address(0x00000000000000000000000000000000000000A1)), 1 ether);
        pays[1] = IonVault.Payout(keccak256("burn two"), payable(address(0x00000000000000000000000000000000000000b2)), 250000000000000000);
        bytes32[] memory tags = new bytes32[](1);
        tags[0] = tag;
        uint256 refundCap = 3000000000000000;
        bytes32 digest = keccak256(abi.encode(keccak256("MoneroUSD IonVault pay v1"), block.chainid, address(vault), vault.epoch(), keccak256(abi.encode(pays)), keccak256(abi.encode(tags)), refundCap));
        emit log_named_bytes32("payoutsHash", keccak256(abi.encode(pays)));
        emit log_named_bytes32("tagsHash", keccak256(abi.encode(tags)));
        emit log_named_bytes32("payDigest", digest);
        bytes memory call = abi.encodeCall(IonVault.pay, (pays, tags, refundCap, currentSet(), signTwo(digest, "paySig")));
        emit log_named_bytes("payCalldata", call);
        (bool funded, ) = address(vault).call{value: 5 ether}("");
        require(funded, "fund");
        (bool waiting, ) = vault.depositAddress(tag).call{value: 1 ether}("");
        require(waiting, "deposit");
        (bool ok, ) = address(vault).call(call);
        require(ok, "the printed pay call is taken");
        require(vault.paid(pays[0].id) && vault.paid(pays[1].id), "both ids are recorded as paid");
        require(address(0x00000000000000000000000000000000000000A1).balance == 1 ether, "the first payout arrived");
        require(vault.depositAddress(tag).balance == 0, "the waiting deposit was swept into the vault");
    }

    /// A hand-over to a set of two (the first and the third custodian): printed, then taken by the contract.
    function rotateVectors() internal {
        IonVault.SignerSet memory next;
        next.signers = new address[](2);
        next.weights = new uint256[](2);
        next.signers[0] = who[0]; next.signers[1] = who[2];
        next.weights[0] = 4; next.weights[1] = 6;
        next.threshold = 7;
        bytes32 nextHash = keccak256(abi.encode(next.signers, next.weights, next.threshold, uint64(1)));
        emit log_named_bytes32("nextSetHash", nextHash);
        bytes32 digest = keccak256(abi.encode(keccak256("MoneroUSD IonVault rotate v1"), block.chainid, address(vault), vault.epoch(), nextHash));
        emit log_named_bytes32("rotateDigest", digest);
        bytes memory call = abi.encodeCall(IonVault.rotate, (next, currentSet(), signTwo(digest, "rotateSig")));
        emit log_named_bytes("rotateCalldata", call);
        (bool ok, ) = address(vault).call(call);
        require(ok && vault.epoch() == 1 && vault.signerSetHash() == nextHash, "the printed hand-over is taken");
    }

    function test_vectors() public {
        setUpVault();
        payVectors();
        rotateVectors();
        bytes32[] memory one = new bytes32[](1);
        one[0] = tag;
        emit log_named_bytes("sweepCalldata", abi.encodeCall(IonVault.sweep, (one)));
        emit log_named_bytes("depositCalldata", abi.encodeCall(IonVault.deposit, (tag)));
        emit log_named_bytes("collectCalldata", abi.encodeCall(IonVault.collect, ()));
        emit log_named_bytes32("paidEventTopic", keccak256("Paid(bytes32,address,uint256)"));
        emit log_named_bytes32("setAsideEventTopic", keccak256("SetAside(bytes32,address,uint256)"));
        emit log_named_bytes32("depositedEventTopic", keccak256("Deposited(bytes32,uint256)"));
        emit log_named_bytes32("sweptEventTopic", keccak256("Swept(bytes32,address,uint256)"));
        emit log_named_bytes32("rotatedEventTopic", keccak256("Rotated(uint64,bytes32)"));
    }

    receive() external payable {}
}
