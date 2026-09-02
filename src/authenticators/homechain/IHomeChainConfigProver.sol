// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Trust seam for {HomeChainAuthenticator}: proves the {Keystore.ActorConfig} an actor holds on a
///         remote ("home") chain, so an L2 can honor a key that was authorized on L1.
///
///         An implementation verifies `proof` (e.g. an L1 block header via the OP-stack `L1Block` predeploy,
///         then an MPT account + storage proof of the home Keystore's actor slot) and returns the proven config
///         exactly as `Keystore.getActorConfig(homeAccount, actorId)` would report it on `homeChainId` — i.e. the
///         all-zero config (authenticator == address(0)) for an actor that is not live there.
///
///         This example ships a {MockHomeChainConfigProver}; a real verifier implements the same interface.
interface IHomeChainConfigProver {
    /// @notice Returns the config proven for `actorId` on `homeAccount` at `homeChainId`.
    ///
    /// @dev MUST revert on a malformed/failed proof. MUST return authenticator == address(0) (and zeroed
    ///      expiry/scope) when the proof shows the actor is not live on the home chain. The returned
    ///      (authenticator, expiry, scope) mirror the packed {Keystore.ActorConfig} layout.
    ///
    /// @param homeChainId  Chain id whose Keystore state is being proven.
    /// @param homeAccount  Account on the home chain whose actor set is consulted.
    /// @param actorId      Actor identifier resolved on the home chain.
    /// @param proof        Verifier-specific proof bytes.
    ///
    /// @return authenticator The authenticator the actor is bound to on the home chain (address(0) = not live).
    /// @return expiry        The actor's expiry on the home chain (0 = no expiry).
    /// @return scope         The actor's scope on the home chain (0x00 = unrestricted admin).
    function proveActorConfig(uint256 homeChainId, address homeAccount, bytes32 actorId, bytes calldata proof)
        external
        view
        returns (address authenticator, uint48 expiry, uint16 scope);
}
