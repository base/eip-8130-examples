// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "eip-8130/AccountConfiguration.sol";
import {BackwardsCompatible4337Account} from "../src/accounts/erc4337/BackwardsCompatible4337Account.sol";
import {UpgradeableAccount} from "../src/accounts/upgradeable/UpgradeableAccount.sol";
import {UpgradeableProxy} from "../src/accounts/upgradeable/UpgradeableProxy.sol";

/// @dev Nick's deterministic deployment proxy, available at the same address on every EVM chain.
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
bytes32 constant SALT = bytes32(0);

/// @notice Deterministically deploys the example upgradeable and ERC-4337 account implementations.
/// @dev AccountConfiguration is compiled from this repository's pinned eip-8130 submodule and deployed first.
///      Every deployment is idempotent. These contracts are examples only, not canonical EIP-8130 infrastructure.
contract Deploy is Script {
    error Create2DeploymentFailed();

    function _addr(bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, SALT, keccak256(initCode)))))
        );
    }

    function _create2(bytes memory initCode) internal returns (address addr) {
        addr = _addr(initCode);
        if (addr.code.length > 0) return addr;

        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
        if (!ok || addr.code.length == 0) revert Create2DeploymentFailed();
    }

    function _accountConfigurationInit() internal pure returns (bytes memory) {
        return type(AccountConfiguration).creationCode;
    }

    function _upgradeableAccountInit(address accountConfiguration) internal pure returns (bytes memory) {
        return abi.encodePacked(type(UpgradeableAccount).creationCode, abi.encode(accountConfiguration));
    }

    function _backwardsCompatible4337AccountInit(address accountConfiguration) internal pure returns (bytes memory) {
        return abi.encodePacked(type(BackwardsCompatible4337Account).creationCode, abi.encode(accountConfiguration));
    }

    function _erc1167Runtime(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    function _logAddresses(
        address accountConfiguration,
        address upgradeableAccount,
        address backwardsCompatible4337Account
    ) internal pure {
        bytes memory upgradeableProxy = UpgradeableProxy.bytecode(upgradeableAccount);
        bytes memory erc4337Proxy = _erc1167Runtime(backwardsCompatible4337Account);

        console.log("AccountConfiguration:              ", accountConfiguration);
        console.log("UpgradeableAccount implementation:", upgradeableAccount);
        console.log("BackwardsCompatible4337Account:   ", backwardsCompatible4337Account);
        console.log("");
        console.log("UpgradeableAccount proxy bytecode:");
        console.logBytes(upgradeableProxy);
        console.log("keccak256(proxy bytecode):");
        console.logBytes32(keccak256(upgradeableProxy));
        console.log("");
        console.log("BackwardsCompatible4337Account ERC-1167 runtime:");
        console.logBytes(erc4337Proxy);
        console.log("keccak256(ERC-1167 runtime):");
        console.logBytes32(keccak256(erc4337Proxy));
    }

    /// @notice Previews implementation addresses and per-account proxy bytecode without deploying.
    function addresses() public pure {
        address accountConfiguration = _addr(_accountConfigurationInit());
        address upgradeableAccount = _addr(_upgradeableAccountInit(accountConfiguration));
        address backwardsCompatible4337Account = _addr(_backwardsCompatible4337AccountInit(accountConfiguration));

        _logAddresses(accountConfiguration, upgradeableAccount, backwardsCompatible4337Account);
    }

    function run() public {
        vm.startBroadcast();
        address accountConfiguration = _create2(_accountConfigurationInit());
        address upgradeableAccount = _create2(_upgradeableAccountInit(accountConfiguration));
        address backwardsCompatible4337Account = _create2(_backwardsCompatible4337AccountInit(accountConfiguration));
        vm.stopBroadcast();

        _logAddresses(accountConfiguration, upgradeableAccount, backwardsCompatible4337Account);
    }
}
