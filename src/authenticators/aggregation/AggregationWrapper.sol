// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

import {AGGREGATED, Dependency, INLINE} from "./Types.sol";
import {IAggregationContext} from "./IAggregationContext.sol";

/// @notice Draft `AGG_WRAP`: bind a deps commitment into the signed message, then
///         verify a scheme signature (inline or via the block-fact stub) and an
///         optional inner authenticator.
///
///         Data is ABI-encoded {Wrapper} (wire packing is TBD; this is the stub).
///         `message = keccak256(hash ‖ depsCommitment)` is what the scheme signs.
///         `repr` is outside that message so the builder can flip INLINE ↔ AGGREGATED.
contract AggregationWrapper is IAuthenticator {
    struct Wrapper {
        uint8 repr;
        address schemeAuth;
        bytes pubkey;
        bytes signature;
        bytes32 depsCommitment;
        Dependency[] deps;
        address innerAuthenticator;
        bytes innerData;
    }

    IAggregationContext public immutable CTX;

    error InvalidRepr();
    error DepsCommitment();
    error SchemeFailed();
    error InnerFailed();

    constructor(address ctx) {
        CTX = IAggregationContext(ctx);
    }

    function commitDeps(Dependency[] memory deps) public pure returns (bytes32) {
        return keccak256(abi.encode(deps));
    }

    function actorIdOf(address schemeAuth, bytes memory pubkey) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(schemeAuth, pubkey));
    }

    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        Wrapper memory w = abi.decode(data, (Wrapper));
        if (w.depsCommitment != commitDeps(w.deps)) revert DepsCommitment();

        bytes32 message = keccak256(abi.encodePacked(hash, w.depsCommitment));
        actorId = actorIdOf(w.schemeAuth, w.pubkey);

        if (w.repr == INLINE) {
            bytes32 got = IAuthenticator(w.schemeAuth).authenticate(message, _inlineBlob(w.pubkey, w.signature));
            if (got == bytes32(0) || got != actorId) revert SchemeFailed();
        } else if (w.repr == AGGREGATED) {
            if (!CTX.isFactProven(w.schemeAuth, message, actorId)) revert SchemeFailed();
        } else {
            revert InvalidRepr();
        }

        if (w.innerAuthenticator != address(0)) {
            if (IAuthenticator(w.innerAuthenticator).authenticate(hash, w.innerData) == bytes32(0)) {
                revert InnerFailed();
            }
        }
    }

    function _inlineBlob(bytes memory pubkey, bytes memory signature) internal pure returns (bytes memory) {
        return abi.encodePacked(INLINE, pubkey, signature);
    }
}
