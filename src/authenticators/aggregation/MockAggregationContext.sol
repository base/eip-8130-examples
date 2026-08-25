// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Dependency} from "./Types.sol";
import {IAggregationContext} from "./IAggregationContext.sol";

/// @notice Stand-in for the protocol: a recursive STARK's public inputs plus the
///         parsed `AGG_WRAP` dependency list. Tests and the demo call {proveFact}
///         instead of producing a proof.
contract MockAggregationContext is IAggregationContext {
    mapping(bytes32 => bool) public facts;
    mapping(bytes32 => bool) public depsProven;

    Dependency[] public deps;

    function proveFact(address scheme, bytes32 message, bytes32 actorId) external {
        facts[_factKey(scheme, message, actorId)] = true;
    }

    function proveDependency(bytes32 hash, bytes32 actorId) external {
        depsProven[_depKey(hash, actorId)] = true;
    }

    function setDependencies(Dependency[] calldata next) external {
        delete deps;
        for (uint256 i; i < next.length; i++) {
            deps.push(next[i]);
        }
    }

    function isFactProven(address scheme, bytes32 message, bytes32 actorId) external view returns (bool) {
        return facts[_factKey(scheme, message, actorId)];
    }

    function isDependencyProven(bytes32 hash, bytes32 actorId) external view returns (bool) {
        return depsProven[_depKey(hash, actorId)];
    }

    function dependencyCount() external view returns (uint256) {
        return deps.length;
    }

    function dependencyAt(uint256 i) external view returns (uint8 kind, bytes32 hash, bytes32 actorId) {
        Dependency storage d = deps[i];
        return (d.kind, d.hash, d.actorId);
    }

    function _factKey(address scheme, bytes32 message, bytes32 actorId) internal pure returns (bytes32) {
        return keccak256(abi.encode(scheme, message, actorId));
    }

    function _depKey(bytes32 hash, bytes32 actorId) internal pure returns (bytes32) {
        return keccak256(abi.encode(hash, actorId));
    }
}
