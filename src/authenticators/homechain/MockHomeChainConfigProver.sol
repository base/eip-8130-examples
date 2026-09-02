// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IHomeChainConfigProver} from "./IHomeChainConfigProver.sol";

/// @notice Test/demo prover for {HomeChainAuthenticator}. Stands in for a real home-chain state-proof verifier
///         (OP-stack `L1Block` header ‖ MPT account/storage proof of the home Keystore) by letting a test seed
///         the home config directly. `proof` is ignored — the mock is the trust boundary, exactly like
///         {MockAggregationContext} in `aggregation/`.
///
///         NOT for production: this trusts whoever calls {setActorConfig}, so it proves nothing on its own.
contract MockHomeChainConfigProver is IHomeChainConfigProver {
    struct StoredConfig {
        address authenticator;
        uint48 expiry;
        uint16 scope;
    }

    /// @dev keccak256(homeChainId, homeAccount, actorId) => proven config.
    mapping(bytes32 => StoredConfig) internal _configs;

    /// @notice Seed the config the mock will "prove" for a home actor. Clear it by passing address(0).
    function setActorConfig(
        uint256 homeChainId,
        address homeAccount,
        bytes32 actorId,
        address authenticator,
        uint48 expiry,
        uint16 scope
    ) external {
        _configs[_key(homeChainId, homeAccount, actorId)] = StoredConfig(authenticator, expiry, scope);
    }

    /// @inheritdoc IHomeChainConfigProver
    function proveActorConfig(uint256 homeChainId, address homeAccount, bytes32 actorId, bytes calldata /* proof */ )
        external
        view
        returns (address authenticator, uint48 expiry, uint16 scope)
    {
        StoredConfig memory c = _configs[_key(homeChainId, homeAccount, actorId)];
        return (c.authenticator, c.expiry, c.scope);
    }

    function _key(uint256 homeChainId, address homeAccount, bytes32 actorId) private pure returns (bytes32) {
        return keccak256(abi.encode(homeChainId, homeAccount, actorId));
    }
}
