// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";

import {AlwaysValidAuthenticator} from "../../../src/authenticators/pure/AlwaysValidAuthenticator.sol";
import {AGGREGATED, DEP_SENDER, Dependency, INLINE} from "../../../src/authenticators/aggregation/Types.sol";
import {AggregationWrapper} from "../../../src/authenticators/aggregation/AggregationWrapper.sol";
import {AggregatableBLSAuthenticator} from "../../../src/authenticators/aggregation/AggregatableBLSAuthenticator.sol";
import {HashSchemeAuthenticator} from "../../../src/authenticators/aggregation/HashSchemeAuthenticator.sol";
import {MockAggregationContext} from "../../../src/authenticators/aggregation/MockAggregationContext.sol";
import {BLSAggregate} from "../../../src/authenticators/pure/BLSAggregate.sol";

contract AggregationTest is Test {
    MockAggregationContext internal ctx;
    HashSchemeAuthenticator internal scheme;
    AggregationWrapper internal wrap;
    AlwaysValidAuthenticator internal inner;

    bytes32 internal pk = keccak256("pk");
    bytes32 internal hash = keccak256("tx");

    function setUp() public {
        ctx = new MockAggregationContext();
        scheme = new HashSchemeAuthenticator(address(ctx));
        wrap = new AggregationWrapper(address(ctx));
        inner = new AlwaysValidAuthenticator();
    }

    function test_hashScheme_inlineAndAggregatedSameActor() public {
        bytes32 actorId = scheme.actorIdOf(pk);
        bytes32 sig = keccak256(abi.encodePacked(hash, pk));
        assertEq(scheme.authenticate(hash, abi.encodePacked(INLINE, pk, sig)), actorId);

        bytes32 aggregated = scheme.authenticate(hash, abi.encodePacked(AGGREGATED, actorId));
        assertEq(aggregated, bytes32(0)); // no fact yet

        ctx.proveFact(address(scheme), hash, actorId);
        assertEq(scheme.authenticate(hash, abi.encodePacked(AGGREGATED, actorId)), actorId);
    }

    function test_wrapper_bindsDepsAndInner() public {
        Dependency[] memory deps = new Dependency[](1);
        deps[0] = Dependency({kind: DEP_SENDER, hash: keccak256("permit"), actorId: scheme.actorIdOf(pk)});

        bytes32 depsCommitment = wrap.commitDeps(deps);
        bytes32 message = keccak256(abi.encodePacked(hash, depsCommitment));
        bytes32 sig = keccak256(abi.encodePacked(message, pk));

        AggregationWrapper.Wrapper memory w = AggregationWrapper.Wrapper({
            repr: INLINE,
            schemeAuth: address(scheme),
            pubkey: abi.encodePacked(pk),
            signature: abi.encodePacked(sig),
            depsCommitment: depsCommitment,
            deps: deps,
            innerAuthenticator: address(inner),
            innerData: ""
        });

        bytes32 actorId = wrap.authenticate(hash, abi.encode(w));
        assertEq(actorId, wrap.actorIdOf(address(scheme), abi.encodePacked(pk)));

        w.depsCommitment = bytes32(uint256(1));
        vm.expectRevert(AggregationWrapper.DepsCommitment.selector);
        wrap.authenticate(hash, abi.encode(w));
    }

    function test_wrapper_aggregatedUsesFactOnMessageNotHash() public {
        Dependency[] memory deps = new Dependency[](0);
        bytes32 depsCommitment = wrap.commitDeps(deps);
        bytes32 message = keccak256(abi.encodePacked(hash, depsCommitment));
        bytes32 actorId = wrap.actorIdOf(address(scheme), abi.encodePacked(pk));

        ctx.proveFact(address(scheme), hash, actorId);
        AggregationWrapper.Wrapper memory w = AggregationWrapper.Wrapper({
            repr: AGGREGATED,
            schemeAuth: address(scheme),
            pubkey: abi.encodePacked(pk),
            signature: "",
            depsCommitment: depsCommitment,
            deps: deps,
            innerAuthenticator: address(0),
            innerData: ""
        });
        vm.expectRevert(AggregationWrapper.SchemeFailed.selector);
        wrap.authenticate(hash, abi.encode(w));

        ctx.proveFact(address(scheme), message, actorId);
        assertEq(wrap.authenticate(hash, abi.encode(w)), actorId);
    }

    function test_isDependencyProven_stub() public {
        bytes32 actorId = scheme.actorIdOf(pk);
        bytes32 permit = keccak256("permit");
        assertFalse(ctx.isDependencyProven(permit, actorId));
        ctx.proveDependency(permit, actorId);
        assertTrue(ctx.isDependencyProven(permit, actorId));
    }

    function test_aggregatableBls_inline() public {
        AggregatableBLSAuthenticator bls = new AggregatableBLSAuthenticator(address(ctx));
        bytes32 sk = bytes32(uint256(3));
        bytes32 txHash = keccak256("bls-tx");
        bytes memory pubkey = BLSAggregate.encodeG1(BLSAggregate.pubkey(sk));
        bytes memory sig = BLSAggregate.encodeG2(BLSAggregate.sign(sk, txHash));
        bytes32 actorId = bls.authenticate(txHash, abi.encodePacked(INLINE, pubkey, sig));
        assertEq(actorId, bls.actorIdOf(pubkey));
    }
}
