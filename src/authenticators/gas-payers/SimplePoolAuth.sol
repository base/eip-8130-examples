// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

import {ISimplePool, PoolSplitter} from "../../privacy/SimplePool.sol";
import {IExtendedTransactionContext} from "../interfaces/IExtendedTransactionContext.sol";

/// @notice Payer-scoped authenticator that sponsors a {SimplePool} spend.
///
///         Installed by ANY payer operator as a payer-scoped actor on their own
///         account: record = { actorId: FEE_PAYER, authenticator: this, scope:
///         SPONSOR_PAYER }. The pool itself is TX_CONTEXT-agnostic; all 8130
///         policy lives here. See `src/privacy/` for the pool.
///
///         Transaction shape:
///           payer_auth = SIMPLE_POOL_AUTH (20 bytes, no data; hash unused)
///           phase 0 = [ pool.spend(proof, root, N, value, K),
///                       splitter.payFee(N, payer, fee) ]
///           phase 1+ = splitter.withdraw(N) then K-signed script
///
///         Cannot run against the shipped {ITransactionContext} precompile —
///         see {IExtendedTransactionContext}.
///
///         H5: the proof does not commit to calls; getTransactionSender() == K
///         binds this public proof to this tx.
///         H4: conflictKey() exports N for (payer, N) pending-tx dedup.
contract SimplePoolAuth is IAuthenticator {
    ISimplePool public immutable POOL;
    PoolSplitter public immutable SPLITTER;
    IExtendedTransactionContext public immutable CTX;

    uint256 public immutable MIN_FEE; // operator's floor, wei
    uint256 public immutable MIN_PHASE0_GAS; // worst case of spend()+payFee

    bytes32 public constant FEE_PAYER = keccak256("SIMPLE_POOL_FEE_PAYER_V1");

    bytes4 internal constant SPEND = ISimplePool.spend.selector;
    bytes4 internal constant PAY_FEE = PoolSplitter.payFee.selector;

    error PhaseZeroShape(); // not exactly [spend, payFee]
    error SenderNotEphemeralKey(); // H5
    error TransferNotToPayer(); // checklist 4
    error NullifierMismatch();
    error FeeOutOfBounds();
    error ValueBelowFee(); // checklist 2
    error FeeBelowMaxCost(); // checklist 1a
    error GasBelowPhaseFloor(); // checklist 1b
    error NoteInvalid(); // checklist 3

    constructor(address pool, address ctx, uint256 minFee, uint256 minPhase0Gas) {
        POOL = ISimplePool(pool);
        SPLITTER = ISimplePool(pool).SPLITTER();
        CTX = IExtendedTransactionContext(ctx);
        MIN_FEE = minFee;
        MIN_PHASE0_GAS = minPhase0Gas;
    }

    /// hash: unused. data: empty.
    function authenticate(bytes32, bytes calldata) external view returns (bytes32) {
        IExtendedTransactionContext.Call[][] memory phases = CTX.getTransactionCalls();
        if (phases.length == 0 || phases[0].length != 2) revert PhaseZeroShape();

        IExtendedTransactionContext.Call memory c0 = phases[0][0];
        IExtendedTransactionContext.Call memory c1 = phases[0][1];
        if (c0.to != address(POOL) || bytes4(_sel(c0.data)) != SPEND) revert PhaseZeroShape();
        if (c1.to != address(SPLITTER) || bytes4(_sel(c1.data)) != PAY_FEE) revert PhaseZeroShape();

        (bytes memory proof, uint256 root, uint256 nullifier, uint256 value, address ephemeralSigner) =
            abi.decode(_args(c0.data), (bytes, uint256, uint256, uint256, address));

        (uint256 feeNullifier, address feeTo, uint256 fee) = abi.decode(_args(c1.data), (uint256, address, uint256));

        if (feeNullifier != nullifier) revert NullifierMismatch();
        if (feeTo != CTX.getTransactionPayer()) revert TransferNotToPayer();
        if (CTX.getTransactionSender() != ephemeralSigner) revert SenderNotEphemeralKey();

        if (fee < MIN_FEE) revert FeeOutOfBounds();
        if (value < fee) revert ValueBelowFee();
        if (fee < CTX.maxCost()) revert FeeBelowMaxCost();
        if (CTX.getTransactionGasLimit() < MIN_PHASE0_GAS) revert GasBelowPhaseFloor();

        if (!POOL.isValidSpend(proof, root, nullifier, value, ephemeralSigner)) revert NoteInvalid();

        return FEE_PAYER;
    }

    /// H4: declared conflict key for (payer, N) pending-tx dedup.
    function conflictKey() external view returns (bytes32) {
        IExtendedTransactionContext.Call[][] memory phases = CTX.getTransactionCalls();
        (,, uint256 nullifier,,) = abi.decode(_args(phases[0][0].data), (bytes, uint256, uint256, uint256, address));
        return bytes32(nullifier);
    }

    function _sel(bytes memory cd) internal pure returns (bytes4 s) {
        require(cd.length >= 4);
        assembly {
            s := mload(add(cd, 0x20))
        }
    }

    function _args(bytes memory cd) internal pure returns (bytes memory out) {
        out = new bytes(cd.length - 4);
        for (uint256 i; i < out.length; i++) {
            out[i] = cd[i + 4];
        }
    }
}
