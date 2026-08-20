// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

/// @notice Authenticator that always succeeds — no signature data required.
///
///         Returns a fixed actorId (keccak256("ALWAYS_VALID")). Register this actorId
///         with AlwaysValidAuthenticator on your account to enable keyless submission.
///
///         Use case: keyless privacy relay. Anyone can submit transactions on behalf
///         of the account — gas is paid by a separate payer or acquired during
///         committed_calldata.
///
///         WARNING: An AlwaysValid actor authorizes ANY transaction for the account.
///
/// @dev Minimal transfer of `AlwaysValidVerifier` from base/eip-8130 @ 99d4331.
contract AlwaysValidAuthenticator is IAuthenticator {
    bytes32 public constant ACTOR_ID = keccak256("ALWAYS_VALID");

    function authenticate(bytes32, bytes calldata) external pure returns (bytes32) {
        return ACTOR_ID;
    }
}
