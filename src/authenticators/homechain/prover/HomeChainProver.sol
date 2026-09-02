// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IHomeChainConfigProver} from "../IHomeChainConfigProver.sol";
import {IChainProver} from "./IChainProver.sol";
import {IL1StateOracle} from "./IL1StateOracle.sol";
import {StateProofLib} from "./StateProofLib.sol";

/// @notice Real (state-proof) implementation of {IHomeChainConfigProver} for {HomeChainAuthenticator}, supporting
///         L1 and L2 home chains (Optimism, Base, Arbitrum) via a chainId => {IChainProver} registry.
///
///         Flow for `proveActorConfig`:
///           1. Get a trusted L1 state root from the local-chain L1 oracle.
///           2. Look up the home chain's {IChainProver} and derive the home Keystore's storage root
///              (recursively for L2 homes: L1-committed output/confirmData -> L2 state root -> Keystore account).
///           3. Storage-prove `_actors[actorId][homeAccount].config` against that storage root and decode it.
///
///         The home {Keystore} is at the same deterministic CREATE2 address on every chain, so it is a single
///         immutable here.
///
///         Unaudited example. A malformed/failed proof reverts (the {HomeChainAuthenticator} calls this via
///         try/catch and fails closed). Absence of an actor cannot be positively proven (no non-inclusion proof):
///         a missing actor simply reverts, which the authenticator treats as "not authorized".
contract HomeChainProver is IHomeChainConfigProver {
    /// @notice Local-chain source of a trusted L1 state root.
    IL1StateOracle public immutable L1_ORACLE;

    /// @notice The Keystore address, identical across chains (deterministic CREATE2).
    address public immutable KEYSTORE;

    /// @notice Owner allowed to register chain provers.
    address public immutable OWNER;

    /// @notice homeChainId => prover that derives that chain's Keystore storage root. The "chain id to bridge map".
    mapping(uint256 homeChainId => IChainProver) public chainProver;

    /// @notice Per-call proof envelope.
    /// @param l1HeaderProof Passed to the L1 oracle to establish the L1 state root.
    /// @param chainProof    Passed to the home chain's {IChainProver} to derive the Keystore storage root.
    /// @param storageProof  Storage inclusion proof of the actor-config slot against that storage root.
    struct Proof {
        bytes l1HeaderProof;
        bytes chainProof;
        bytes[] storageProof;
    }

    /// @notice No chain prover is registered for the requested home chain.
    error UnknownHomeChain(uint256 homeChainId);

    /// @notice Caller is not the owner.
    error Unauthorized();

    event ChainProverSet(uint256 indexed homeChainId, address indexed prover);

    constructor(address l1Oracle, address keystore, address owner) {
        L1_ORACLE = IL1StateOracle(l1Oracle);
        KEYSTORE = keystore;
        OWNER = owner;
    }

    /// @notice Register (or clear, with address(0)) the prover for a home chain.
    function setChainProver(uint256 homeChainId, IChainProver prover) external {
        if (msg.sender != OWNER) revert Unauthorized();
        chainProver[homeChainId] = prover;
        emit ChainProverSet(homeChainId, address(prover));
    }

    /// @inheritdoc IHomeChainConfigProver
    function proveActorConfig(uint256 homeChainId, address homeAccount, bytes32 actorId, bytes calldata proof)
        external
        view
        returns (address authenticator, uint48 expiry, uint16 scope)
    {
        IChainProver cp = chainProver[homeChainId];
        if (address(cp) == address(0)) revert UnknownHomeChain(homeChainId);

        Proof memory p = abi.decode(proof, (Proof));

        // 1. Trusted L1 state root from the local chain.
        bytes32 l1StateRoot = L1_ORACLE.l1StateRoot(p.l1HeaderProof);

        // 2. Home Keystore storage root (recursive for L2 homes).
        bytes32 storageRoot = cp.proveKeystoreStorageRoot(l1StateRoot, KEYSTORE, p.chainProof);

        // 3. Storage-prove and decode the actor config.
        bytes32 slot = StateProofLib.actorConfigSlot(actorId, homeAccount);
        uint256 word = StateProofLib.storageWord(storageRoot, slot, p.storageProof);
        return StateProofLib.decodeActorConfig(word);
    }
}
