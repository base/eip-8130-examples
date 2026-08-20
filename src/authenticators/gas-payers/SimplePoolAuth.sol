// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

import {IExtendedTransactionContext} from "../interfaces/IExtendedTransactionContext.sol";

// ---------------------------------------------------------------------------
// SimplePoolAuth + SimplePool (v4: external payer, payer-agnostic pool)
//
// Example privacy pool: a toy encrypted-note pool plus the payer-scoped
// authenticator that sponsors spends. The pool itself is TX_CONTEXT-agnostic.
//
// Roles:
//   sender  = addr(K), ephemeral, one per spend, holds nothing beforehand
//   payer   = ANY external 8130 account whose operator installed
//             SimplePoolAuth as a payer-scoped actor; fronts gas for fees
//   pool    = a PLAIN contract: deposits, self-verifying spend, and a
//             validity view. Zero TX_CONTEXT awareness; deployable today.
//             All 8130-specific logic lives in the authenticator.
//
// Transaction shape:
//   payer_auth = SIMPLE_POOL_AUTH (20 bytes, no data; hash unused)
//   calls (phases):
//     phase 0 = [ pool.spend(proof, root, N, value, K),     // pays K
//                 NATIVE_TRANSFER(payer, fee) ]             // K pays payer
//     phase 1+ = K-signed script (swap, re-deposit, whatever)
//
// Solvency chain making phase 0 unfailable for honest spends:
//   spend() credits `value` to K at calls[0][0]; the policy required
//   value >= fee; nothing executes in between; therefore the transfer at
//   calls[0][1] cannot lack balance.
//
// The payer's checklist and its discharge:
//   1. total gas covered ....... fee >= ctx.maxCost() AND
//                                getTransactionGasLimit() >= MIN_PHASE0_GAS
//                                (spend now verifies the proof at
//                                execution, so the floor covers verify +
//                                transfer; an OOG inside phase 0 would
//                                otherwise be free griefing by a valid
//                                note holder, since a revert leaves N
//                                unspent and retryable)
//   2. note covers the fee ..... value >= fee
//   3. note is valid ........... STATICCALL pool.isValidSpend at
//                                validation: groth verify + knownRoots +
//                                !spent. The two storage reads are
//                                MONOTONE: knownRoots only grows (a
//                                pending tx can never be invalidated by
//                                it) and spent[N] flips valid->invalid
//                                exactly once, at exactly the conflict
//                                event (payer, N) dedup tracks. Monotone
//                                reads are the benign class of validation
//                                dependency; EIP-8272 recent roots are the
//                                bounded-window hardening of this class,
//                                permanent knownRoots is the unbounded-
//                                window simple version. Without the root
//                                check at validation, a fabricated
//                                tree+note+proof passes a bare groth
//                                verify and reverts at execution on the
//                                payer's gas.
//   4. payer actually paid ..... calls[0][1] is pinned as a native
//                                transfer of `fee` to `getTransactionPayer()`
//                                — the installing account — so one deployment
//                                serves every payer operator.
//   5. nothing else in phase 0 . calls[0].length == 2, both calls pinned.
//
// What v4 DELETED relative to the claim-based design, and why:
//   - guard latch + payer gate + config invariant: spend() verifies its
//     own proof, so no unbacked path into it exists; direct calls with
//     valid proofs are just legitimate spends.
//   - claim machinery + C_change + reclaim: failure custody is "the ETH
//     is at K", the user's own key. (The claim/re-shield design remains
//     the right shape for the full pool where withdrawals should not park
//     value at a public address; here simplicity wins.)
//   - maxFee circuit cap: fee is the transfer amount in a call K signs;
//     the user controls it directly. Circuit publics shrink to
//     (root, N, value, K).
//
// SPEC GAP (flagged): Call = (to, data) has no value field, so the
// envelope has no native way for K to move ETH. NATIVE_TRANSFER below is
// an assumed canonical precompile (data = abi.encode(to, amount), moves
// ETH from the executing sender account, reverts only on insufficient
// balance). The transaction spec must pick this or a value field on Call.
//
// TX_CONTEXT GAP: this authenticator cannot run against the shipped
// {ITransactionContext} precompile — see {IExtendedTransactionContext}.
//
// Retained from earlier iterations:
//   H5 (lifted proof): the proof does not commit to calls; only
//   getTransactionSender() == K ties this public proof to this tx.
//   H4 (same-note concurrency): conflictKey() exports N for (payer, N)
//   pending-tx dedup.
// ---------------------------------------------------------------------------

// Assumed canonical native-transfer precompile (see SPEC GAP above).
address constant NATIVE_TRANSFER = address(0x000000000000000000000000000000000000E720);

// Installed by ANY payer operator as a payer-scoped actor on their own
// account: record = { actorId: FEE_PAYER, authenticator: this, scope:
// SPONSOR_PAYER }. The operator's other actors (admin, profit sweep) are
// authenticated separately and are none of this policy's business.
contract SimplePoolAuth is IAuthenticator {
    ISimplePool public immutable POOL;
    IExtendedTransactionContext public immutable CTX;

    uint256 public immutable MIN_FEE; // operator's floor, wei
    uint256 public immutable MIN_PHASE0_GAS; // worst case of spend()+transfer

    bytes32 public constant FEE_PAYER = keccak256("SIMPLE_POOL_FEE_PAYER_V1");

    bytes4 internal constant SPEND = ISimplePool.spend.selector;

    error PhaseZeroShape(); // not exactly [spend, transfer]
    error SenderNotEphemeralKey(); // H5
    error TransferNotToPayer(); // checklist 4
    error FeeOutOfBounds();
    error ValueBelowFee(); // checklist 2
    error FeeBelowMaxCost(); // checklist 1a
    error GasBelowPhaseFloor(); // checklist 1b
    error NoteInvalid(); // checklist 3

    constructor(address pool, address ctx, uint256 minFee, uint256 minPhase0Gas) {
        POOL = ISimplePool(pool);
        CTX = IExtendedTransactionContext(ctx);
        MIN_FEE = minFee;
        MIN_PHASE0_GAS = minPhase0Gas;
    }

    /// hash: unused. data: empty.
    function authenticate(bytes32, bytes calldata) external view returns (bytes32) {
        // ---- phase 0 shape: exactly [pool.spend, native transfer] ----
        IExtendedTransactionContext.Call[][] memory phases = CTX.getTransactionCalls();
        if (phases.length == 0 || phases[0].length != 2) revert PhaseZeroShape();

        IExtendedTransactionContext.Call memory c0 = phases[0][0];
        IExtendedTransactionContext.Call memory c1 = phases[0][1];
        if (c0.to != address(POOL) || bytes4(_sel(c0.data)) != SPEND) revert PhaseZeroShape();
        if (c1.to != NATIVE_TRANSFER) revert PhaseZeroShape();

        (bytes memory proof, uint256 root, uint256 nullifier, uint256 value, address ephemeralSigner) =
            abi.decode(_args(c0.data), (bytes, uint256, uint256, uint256, address));

        (address feeTo, uint256 fee) = abi.decode(c1.data, (address, uint256));

        // ---- checklist 4: the transfer pays THIS payer ----
        if (feeTo != CTX.getTransactionPayer()) revert TransferNotToPayer();

        // ---- H5: bind the public proof to K's transaction ----
        if (CTX.getTransactionSender() != ephemeralSigner) revert SenderNotEphemeralKey();

        // ---- economics (checklist 1, 2) ----
        if (fee < MIN_FEE) revert FeeOutOfBounds();
        if (value < fee) revert ValueBelowFee();
        if (fee < CTX.maxCost()) revert FeeBelowMaxCost();
        if (CTX.getTransactionGasLimit() < MIN_PHASE0_GAS) revert GasBelowPhaseFloor();

        // ---- checklist 3: note validity, via the pool's own view ----
        // groth + knownRoots (monotone-growing) + !spent (monotone once).
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

// -------------------------------- The pool ----------------------------------

interface ISimplePool {
    function spend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address payable recipient)
        external;

    function isValidSpend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address recipient)
        external
        view
        returns (bool);
}

// Stands in for a compiled circuit's verifier. Pure code. MUST range-check
// field-element inputs (< p) against input aliasing.
interface INoteVerifier {
    function verifySpend(
        bytes calldata proof,
        uint256 root,
        uint256 nullifier,
        uint256 value, // circuit-bound
        address recipient // circuit-bound: K
    )
        external
        view
        returns (bool);
}

// Imaginary note scheme (example privacy pool):
//   note       = (value, secret)
//   commitment = H(NOTE_DOMAIN, value, secret)
//   nullifier  = H(NULL_DOMAIN, secret)
//   proof: "commitment is in the tree at `root`, nullifier == N, and I
//           bind publics (value, recipient=K)."
// All historical roots remain valid forever (knownRoots): a genuine proof
// can never fail the root check, so the honest revert surface of spend()
// is exactly {AlreadySpent} (lost race on N).
contract SimplePool {
    INoteVerifier public immutable VERIFIER;

    mapping(uint256 => bool) public knownRoots; // permanent, monotone-growing
    uint256 public currentRoot;
    mapping(uint256 => bool) public spent; // permanent nullifier set

    event Deposited(uint256 commitment, uint256 newRoot);
    event Nullified(uint256 indexed nullifier, address recipient, uint256 value);

    error UnknownRoot();
    error AlreadySpent();
    error ProofInvalid();
    error PayoutFailed();

    constructor(address verifier) {
        VERIFIER = INoteVerifier(verifier);
        knownRoots[0] = true;
    }

    // ---- deposit path (public, boring) ----
    function deposit(uint256 commitment) external payable {
        currentRoot = uint256(keccak256(abi.encode(currentRoot, commitment)));
        knownRoots[currentRoot] = true; // stand-in for real tree insertion
        emit Deposited(commitment, currentRoot);
    }

    // ---- self-verifying spend: callable by ANYONE with a valid proof ----
    // No latch, no payer gate, no TX_CONTEXT: there is no unbacked path to
    // guard, so a direct call with a valid proof is simply a legitimate
    // spend. The 8130 flow pins this as calls[0][0]; the contract neither
    // knows nor cares.
    function spend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address payable recipient)
        external
    {
        if (!knownRoots[root]) revert UnknownRoot(); // unreachable for real proofs
        if (spent[nullifier]) revert AlreadySpent(); // lost race on N
        if (!VERIFIER.verifySpend(proof, root, nullifier, value, recipient)) {
            revert ProofInvalid(); // unreachable if vetted
        }

        spent[nullifier] = true;
        emit Nullified(nullifier, recipient, value);
        (bool ok,) = recipient.call{value: value}("");
        if (!ok) revert PayoutFailed(); // unreachable: K is a fresh native
        // account and cannot refuse ETH
    }

    // ---- the validity view the policy STATICCALLs at validation ----
    function isValidSpend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address recipient)
        external
        view
        returns (bool)
    {
        return knownRoots[root] && !spent[nullifier] && VERIFIER.verifySpend(proof, root, nullifier, value, recipient);
    }

    function isSpent(uint256 nullifier) external view returns (bool) {
        return spent[nullifier];
    }

    function isKnownRoot(uint256 root) external view returns (bool) {
        return knownRoots[root];
    }

    receive() external payable {}
}
