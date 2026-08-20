// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";

import {INoteVerifier, PoolSplitter, SimplePool} from "../../../src/privacy/SimplePool.sol";
import {SimplePoolAuth} from "../../../src/authenticators/gas-payers/SimplePoolAuth.sol";

contract MockNoteVerifier is INoteVerifier {
    bool public ok = true;

    function set(bool v) external {
        ok = v;
    }

    function verifySpend(bytes calldata, uint256, uint256, uint256, address) external view returns (bool) {
        return ok;
    }
}

contract SimplePoolTest is Test {
    MockNoteVerifier internal verifier;
    SimplePool internal pool;
    PoolSplitter internal splitter;

    address internal k = makeAddr("K");
    address internal payer = makeAddr("payer");

    function setUp() public {
        verifier = new MockNoteVerifier();
        pool = new SimplePool(address(verifier));
        splitter = pool.SPLITTER();
    }

    function test_deposit_bindsMsgValueAndRejectsZero() public {
        vm.expectRevert(SimplePool.ZeroDeposit.selector);
        pool.deposit{value: 0}(1);

        pool.deposit{value: 1 ether}(1);
        assertEq(address(pool).balance, 1 ether);
        uint256 commitment = uint256(keccak256(abi.encode(pool.NOTE_DOMAIN(), uint256(1 ether), uint256(1))));
        uint256 root = uint256(keccak256(abi.encode(uint256(0), commitment)));
        assertTrue(pool.isKnownRoot(root));
        assertEq(pool.currentRoot(), root);
    }

    function test_spend_creditsSplitterNotRecipient() public {
        pool.deposit{value: 2 ether}(1);
        uint256 root = pool.currentRoot();

        vm.deal(k, 0);
        pool.spend("", root, 7, 2 ether, payable(k));

        assertEq(address(k).balance, 0);
        assertEq(address(pool).balance, 0);
        assertEq(address(splitter).balance, 2 ether);
        (address recipient, uint256 amount) = splitter.credits(7);
        assertEq(recipient, k);
        assertEq(amount, 2 ether);
        assertTrue(pool.isSpent(7));
    }

    function test_payFee_onlyRecipientThenWithdrawRemainder() public {
        pool.deposit{value: 2 ether}(1);
        pool.spend("", pool.currentRoot(), 7, 2 ether, payable(k));

        vm.expectRevert(PoolSplitter.NotRecipient.selector);
        splitter.payFee(7, payable(payer), 0.5 ether);

        vm.prank(k);
        splitter.payFee(7, payable(payer), 0.5 ether);
        assertEq(payer.balance, 0.5 ether);

        vm.prank(k);
        splitter.withdraw(7);
        assertEq(k.balance, 1.5 ether);
        assertEq(address(splitter).balance, 0);
    }

    function test_isValidSpend_requiresLiquidityAndUnspent() public {
        pool.deposit{value: 1 ether}(1);
        uint256 root = pool.currentRoot();
        address recipient = k;

        assertTrue(pool.isValidSpend("", root, 7, 1 ether, recipient));
        assertFalse(pool.isValidSpend("", root, 7, 2 ether, recipient)); // balance check
        assertFalse(pool.isValidSpend("", root, 7, 0, recipient)); // zero spend

        pool.spend("", root, 7, 1 ether, payable(recipient));
        assertFalse(pool.isValidSpend("", root, 7, 1 ether, recipient)); // spent
    }

    function test_spend_revertsIfValueExceedsBalance() public {
        pool.deposit{value: 1 ether}(1);
        uint256 root = pool.currentRoot();
        vm.expectRevert(SimplePool.InsufficientLiquidity.selector);
        pool.spend("", root, 7, 2 ether, payable(k));
    }

    function test_authConstructsAgainstPoolSplitter() public {
        SimplePoolAuth auth = new SimplePoolAuth(address(pool), address(0x8130), 1, 100_000);
        assertEq(address(auth.SPLITTER()), address(pool.SPLITTER()));
        assertEq(auth.FEE_PAYER(), keccak256("SIMPLE_POOL_FEE_PAYER_V1"));
    }
}
