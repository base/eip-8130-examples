// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script, console} from "forge-std/Script.sol";

import {AGGREGATED, DEP_SENDER, Dependency, INLINE} from "../src/authenticators/aggregation/Types.sol";
import {AggregationWrapper} from "../src/authenticators/aggregation/AggregationWrapper.sol";
import {HashSchemeAuthenticator} from "../src/authenticators/aggregation/HashSchemeAuthenticator.sol";
import {MockAggregationContext} from "../src/authenticators/aggregation/MockAggregationContext.sol";

/// @notice Draft-shaped demo: same actorId inline or aggregated; wrapper binds deps;
///         MockAggregationContext stubs the block STARK + isDependencyProven.
///
///         Run: forge script script/SignatureAggregationDemo.s.sol
contract SignatureAggregationDemo is Script {
    function run() external {
        MockAggregationContext ctx = new MockAggregationContext();
        HashSchemeAuthenticator scheme = new HashSchemeAuthenticator(address(ctx));
        AggregationWrapper wrap = new AggregationWrapper(address(ctx));

        bytes32 pk = keccak256("demo-pk");
        bytes32 actorId = scheme.actorIdOf(pk);
        bytes32 txHash = keccak256("eip-8130-tx");

        bytes32 inlineSig = keccak256(abi.encodePacked(txHash, pk));
        bytes memory inlineAuth = abi.encodePacked(address(scheme), INLINE, pk, inlineSig);
        bytes memory aggregatedAuth = abi.encodePacked(address(scheme), AGGREGATED, actorId);

        console.log("=== signature-aggregation draft stub ===");
        console.log("inline sender_auth bytes", inlineAuth.length);
        console.log("aggregated sender_auth bytes", aggregatedAuth.length);
        console.log("same actorId", scheme.authenticate(txHash, abi.encodePacked(INLINE, pk, inlineSig)) == actorId);

        ctx.proveFact(address(scheme), txHash, actorId);
        require(scheme.authenticate(txHash, abi.encodePacked(AGGREGATED, actorId)) == actorId);

        Dependency[] memory deps = new Dependency[](1);
        deps[0] = Dependency({kind: DEP_SENDER, hash: keccak256("permit"), actorId: actorId});
        bytes32 depsCommitment = wrap.commitDeps(deps);
        bytes32 message = keccak256(abi.encodePacked(txHash, depsCommitment));
        bytes32 wrapSig = keccak256(abi.encodePacked(message, pk));

        AggregationWrapper.Wrapper memory w = AggregationWrapper.Wrapper({
            repr: INLINE,
            schemeAuth: address(scheme),
            pubkey: abi.encodePacked(pk),
            signature: abi.encodePacked(wrapSig),
            depsCommitment: depsCommitment,
            deps: deps,
            innerAuthenticator: address(0),
            innerData: ""
        });
        require(wrap.authenticate(txHash, abi.encode(w)) == actorId);

        w.repr = AGGREGATED;
        w.signature = "";
        ctx.proveFact(address(scheme), message, actorId);
        require(wrap.authenticate(txHash, abi.encode(w)) == actorId);

        ctx.proveDependency(deps[0].hash, actorId);
        require(ctx.isDependencyProven(deps[0].hash, actorId));

        console.log("wrapper inline + aggregated ok; isDependencyProven(permit) = true");
        console.log("builder flipped repr; wallet signed once over keccak(hash || depsCommitment)");
    }
}
