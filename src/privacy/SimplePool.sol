// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Circuit verifier for a SimplePool spend. Implementations MUST range-check
///         field-element inputs (< p) against input aliasing.
interface INoteVerifier {
    function verifySpend(
        bytes calldata proof,
        uint256 root,
        uint256 nullifier,
        uint256 value, // circuit-bound: must equal the deposited msg.value
        address recipient // circuit-bound: K
    )
        external
        view
        returns (bool);
}

interface ISimplePool {
    function spend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address payable recipient)
        external;

    function isValidSpend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address recipient)
        external
        view
        returns (bool);

    function SPLITTER() external view returns (PoolSplitter);
}

/// Escrow for a spent note. Only the pool can credit; only the credited
/// recipient (K) can pay a fee or withdraw the remainder.
contract PoolSplitter {
    address public immutable POOL;

    struct Credit {
        address recipient;
        uint256 amount;
    }

    mapping(uint256 nullifier => Credit) public credits;

    error OnlyPool();
    error NotRecipient();
    error NoCredit();
    error FeeExceedsCredit();
    error PayoutFailed();

    constructor(address pool) {
        POOL = pool;
    }

    function credit(uint256 nullifier, address recipient) external payable {
        if (msg.sender != POOL) revert OnlyPool();
        credits[nullifier] = Credit({recipient: recipient, amount: msg.value});
    }

    /// Phase-0 fee: K sends `fee` from this note's credit to `payer`.
    function payFee(uint256 nullifier, address payable payer, uint256 fee) external {
        Credit storage c = credits[nullifier];
        if (c.recipient == address(0)) revert NoCredit();
        if (msg.sender != c.recipient) revert NotRecipient();
        if (fee > c.amount) revert FeeExceedsCredit();
        c.amount -= fee;
        (bool ok,) = payer.call{value: fee}("");
        if (!ok) revert PayoutFailed();
    }

    /// Later step: K takes the remaining credit.
    function withdraw(uint256 nullifier) external {
        Credit memory c = credits[nullifier];
        if (c.recipient == address(0)) revert NoCredit();
        if (msg.sender != c.recipient) revert NotRecipient();
        delete credits[nullifier];
        (bool ok,) = payable(c.recipient).call{value: c.amount}("");
        if (!ok) revert PayoutFailed();
    }
}

/// @notice Toy privacy pool: public amounts, keccak tree, pluggable proof verifier.
///
///         Note scheme:
///           secretHash  = H(secret)                         (public at deposit)
///           commitment  = H(NOTE_DOMAIN, msg.value, secretHash)  (computed on-chain)
///           nullifier   = H(NULL_DOMAIN, secret)
///           proof: "commitment is in the tree at `root`, nullifier == N, I know
///                   secret behind secretHash, and I bind publics (value, recipient=K)."
///
///         Amounts are public (the contract hashes msg.value itself so a note cannot
///         be worth more than was escrowed). Sender unlink at spend depends on the
///         proof; this file does not ship a circuit. keccak256 stands in for Poseidon.
///
///         `spend` never pays K directly — it credits a pool-owned {PoolSplitter}.
///         No TX_CONTEXT awareness; deployable without EIP-8130.
contract SimplePool {
    bytes32 public constant NOTE_DOMAIN = keccak256("SIMPLE_POOL_NOTE_V1");

    INoteVerifier public immutable VERIFIER;
    PoolSplitter public immutable SPLITTER;

    mapping(uint256 => bool) public knownRoots; // permanent, monotone-growing
    uint256 public currentRoot;
    mapping(uint256 => bool) public spent; // permanent nullifier set

    event Deposited(uint256 commitment, uint256 newRoot, uint256 amount, uint256 secretHash);
    event Nullified(uint256 indexed nullifier, address recipient, uint256 value);

    error ZeroDeposit();
    error ZeroSpend();
    error UnknownRoot();
    error AlreadySpent();
    error ProofInvalid();
    error InsufficientLiquidity();

    constructor(address verifier) {
        VERIFIER = INoteVerifier(verifier);
        SPLITTER = new PoolSplitter(address(this));
        knownRoots[0] = true;
    }

    /// Escrows `msg.value` and inserts a commitment that binds that amount.
    function deposit(uint256 secretHash) external payable {
        if (msg.value == 0) revert ZeroDeposit();
        uint256 commitment = uint256(keccak256(abi.encode(NOTE_DOMAIN, msg.value, secretHash)));
        currentRoot = uint256(keccak256(abi.encode(currentRoot, commitment)));
        knownRoots[currentRoot] = true;
        emit Deposited(commitment, currentRoot, msg.value, secretHash);
    }

    /// Self-verifying spend: credits the splitter for `recipient` (K).
    /// Callable by anyone with a valid proof; a direct call is a legitimate spend.
    function spend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address payable recipient)
        external
    {
        if (value == 0) revert ZeroSpend();
        if (!knownRoots[root]) revert UnknownRoot();
        if (spent[nullifier]) revert AlreadySpent();
        if (address(this).balance < value) revert InsufficientLiquidity();
        if (!VERIFIER.verifySpend(proof, root, nullifier, value, recipient)) revert ProofInvalid();

        spent[nullifier] = true;
        emit Nullified(nullifier, recipient, value);
        SPLITTER.credit{value: value}(nullifier, recipient);
    }

    function isValidSpend(bytes calldata proof, uint256 root, uint256 nullifier, uint256 value, address recipient)
        external
        view
        returns (bool)
    {
        return value != 0 && knownRoots[root] && !spent[nullifier] && address(this).balance >= value
            && VERIFIER.verifySpend(proof, root, nullifier, value, recipient);
    }

    function isSpent(uint256 nullifier) external view returns (bool) {
        return spent[nullifier];
    }

    function isKnownRoot(uint256 root) external view returns (bool) {
        return knownRoots[root];
    }
}
