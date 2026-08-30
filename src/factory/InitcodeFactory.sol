// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "eip-8130/Keystore.sol";

import {InitcodeAccount} from "./InitcodeAccount.sol";

/// @notice CREATE2-deploys an {InitcodeAccount} (constructor runs) then asks it to import itself.
///
///         Recovery is in the calldata actor set, not account storage: at least two unrestricted
///         (scope 0) admins — owner + guardian. Either can rotate the other via the Keystore after
///         import. The factory never holds authority and is not required to finish import.
///
///         `deploy` is the atomic path. `create` stops after CREATE2 so a stranger can still
///         {InitcodeAccount.completeImport} with the committed actors (unbrickable).
contract InitcodeFactory {
    Keystore public immutable KEYSTORE;

    error NeedGuardian();

    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    function actorsHash(Keystore.InitialActor[] calldata actors) public pure returns (bytes32) {
        return keccak256(abi.encode(actors));
    }

    function computeAddress(bytes32 userSalt, bytes32 actorsHash_) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(userSalt, actorsHash_));
        bytes32 initHash =
            keccak256(abi.encodePacked(type(InitcodeAccount).creationCode, abi.encode(address(KEYSTORE), actorsHash_)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initHash)))));
    }

    /// @notice CREATE2 only. Account has code + {ACTORS_HASH}; Keystore is not initialized.
    function create(bytes32 userSalt, Keystore.InitialActor[] calldata actors) public returns (address account) {
        _requireGuardian(actors);
        bytes32 ah = actorsHash(actors);
        bytes32 salt = keccak256(abi.encodePacked(userSalt, ah));
        account = address(new InitcodeAccount{salt: salt}(address(KEYSTORE), ah));
    }

    /// @notice CREATE2 then {completeImport}. Factory → account → Keystore.importAccount.
    function deploy(bytes32 userSalt, Keystore.InitialActor[] calldata actors, uint256 chainId)
        external
        returns (address account)
    {
        account = create(userSalt, actors);
        InitcodeAccount(payable(account)).completeImport(chainId, actors);
    }

    function deploy(bytes32 userSalt, Keystore.InitialActor[] calldata actors) external returns (address account) {
        account = create(userSalt, actors);
        InitcodeAccount(payable(account)).completeImport(block.chainid, actors);
    }

    /// @dev Two unrestricted admins: a second key that can `applySignedAccountChanges` if the first is lost.
    function _requireGuardian(Keystore.InitialActor[] calldata actors) internal pure {
        uint256 admins;
        for (uint256 i; i < actors.length; i++) {
            if (actors[i].scope == 0) admins++;
        }
        if (admins < 2) revert NeedGuardian();
    }
}
