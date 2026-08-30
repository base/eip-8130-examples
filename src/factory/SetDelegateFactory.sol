// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "eip-8130/Keystore.sol";

import {IBootstrap} from "./IBootstrap.sol";

/// @notice Reference factory that deploys EIP-8130 accounts via the EIP-7819 `SETDELEGATE` opcode.
///
///         Flow (atomic, one tx frame):
///           1. `SETDELEGATE(salt, implementation)` places `0xef0100 || implementation` at
///              `keccak256(0xef0100 || factory || salt)[12:]`.
///           2. `account.bootstrap(actorsHash, chainId, initialActors)` runs in the account's storage:
///              it stores the actors in a one-shot latch, calls `Keystore.importAccount` on itself
///              (required: import is `msg.sender`-gated and reads {IKeystoreImport.getImportActors}),
///              and clears the latch. `actorsHash` is the inner hash of EIP-8130's `ActorInitialization`
///              digest and also feeds the SETDELEGATE salt, so the address binds to the actor set.
///
///         The Keystore never knows this factory exists. Squatting defenses:
///           - SETDELEGATE derivation includes `msg.sender` (this factory).
///           - Salt includes a commitment to the actor set.
///           - The full sequence runs in one transaction frame.
///
///         Requires EIP-7819 (`SETDELEGATE`, opcode 0xf6). `_setDelegate` is `virtual` so tests can
///         simulate the opcode via `vm.etch`.
contract SetDelegateFactory {
    /// @dev EIP-7702 delegation indicator prefix used in SETDELEGATE address derivation.
    bytes3 internal constant DELEGATION_INDICATOR = 0xef0100;

    /// @dev Mirrors {Keystore.ACTOR_TYPEHASH}.
    bytes32 internal constant _ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );

    /// @dev Mirrors {Keystore.ACTOR_CONFIG_TYPEHASH}.
    bytes32 internal constant _ACTOR_CONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint48 expiry,uint16 scope)");

    /// @notice Deploy a new EIP-8130 account at a deterministic address on the current chain.
    function deploy(Keystore.InitialActor[] calldata initialActors, address implementation, bytes32 userSalt)
        external
        returns (address account)
    {
        return deploy(initialActors, implementation, userSalt, block.chainid);
    }

    /// @notice Deploy a new EIP-8130 account, binding the import digest to `chainId`.
    /// @param chainId Replay domain for `importAccount`: 0 = multichain, else the current chain.
    function deploy(
        Keystore.InitialActor[] calldata initialActors,
        address implementation,
        bytes32 userSalt,
        uint256 chainId
    ) public returns (address account) {
        bytes32 ah = _actorsHash(initialActors);
        bytes32 salt = keccak256(abi.encodePacked(userSalt, ah));
        account = _setDelegate(salt, implementation);
        IBootstrap(account).bootstrap(ah, chainId, initialActors);
    }

    /// @notice Swap an account's delegate implementation. The account proves authority by being the caller.
    function upgrade(bytes32 userSalt, bytes32 ah, address newImplementation) external {
        bytes32 salt = keccak256(abi.encodePacked(userSalt, ah));
        require(msg.sender == computeAddress(salt), "only account");
        _setDelegate(salt, newImplementation);
    }

    /// @notice Compute the deterministic account address for a given initial actor set and user salt.
    function computeAccount(Keystore.InitialActor[] calldata initialActors, bytes32 userSalt)
        external
        view
        returns (address)
    {
        bytes32 ah = _actorsHash(initialActors);
        return computeAddress(keccak256(abi.encodePacked(userSalt, ah)));
    }

    /// @notice SETDELEGATE-derived address: `keccak256(0xef0100 || factory || salt)[12:]`.
    function computeAddress(bytes32 salt) public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(DELEGATION_INDICATOR, address(this), salt)))));
    }

    /// @notice Inner hash of the EIP-8130 `ActorInitialization` digest (expiry forced to 0).
    function actorsHash(Keystore.InitialActor[] calldata initialActors) external pure returns (bytes32) {
        return _actorsHash(initialActors);
    }

    function _actorsHash(Keystore.InitialActor[] calldata initialActors) internal pure returns (bytes32) {
        bytes32[] memory perActor = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            bytes32 configHash = keccak256(
                abi.encode(_ACTOR_CONFIG_TYPEHASH, initialActors[i].authenticator, uint48(0), initialActors[i].scope)
            );
            perActor[i] = keccak256(
                abi.encode(
                    _ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256(initialActors[i].policyData)
                )
            );
        }
        return keccak256(abi.encodePacked(perActor));
    }

    /// @notice Execute EIP-7819 `SETDELEGATE` (opcode 0xf6). Base implementation reverts; override in tests
    ///         (`vm.etch`) or replace with the Yul builtin once 7819 ships.
    function _setDelegate(bytes32, address) internal virtual returns (address) {
        revert("SETDELEGATE: not implemented; override _setDelegate or wait for EIP-7819 deployment");
    }
}
