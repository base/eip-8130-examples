// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {RLP} from "openzeppelin/utils/RLP.sol";

import {Keystore} from "eip-8130/Keystore.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {HomeChainAuthenticator} from "../../../src/authenticators/homechain/HomeChainAuthenticator.sol";
import {HomeChainProver} from "../../../src/authenticators/homechain/prover/HomeChainProver.sol";
import {StateProofLib} from "../../../src/authenticators/homechain/prover/StateProofLib.sol";
import {L1ChainProver} from "../../../src/authenticators/homechain/prover/L1ChainProver.sol";
import {OpStackChainProver} from "../../../src/authenticators/homechain/prover/OpStackChainProver.sol";
import {ArbitrumChainProver} from "../../../src/authenticators/homechain/prover/ArbitrumChainProver.sol";
import {MockL1StateOracle} from "../../../src/authenticators/homechain/prover/MockL1StateOracle.sol";
import {L1BlockStateOracle, IL1Block} from "../../../src/authenticators/homechain/prover/L1BlockStateOracle.sol";

/// @notice Real state-proof prover tests. Uses OpenZeppelin {TrieProof}/{RLP} for genuine MPT verification, with
///         single-leaf tries built in-test as fixtures. Chain ids: 1 = L1, 10 = OP, 8453 = Base, 42161 = Arbitrum.
contract HomeChainProverTest is KeystoreTest {
    using RLP for *;

    HomeChainProver internal prover;
    MockL1StateOracle internal l1Oracle;
    HomeChainAuthenticator internal auth;

    address internal constant HOME_KEYSTORE = address(0x8130); // same CREATE2 addr on every chain
    address internal constant OP_OUTPUT_ORACLE = address(0x090B);
    address internal constant BASE_OUTPUT_ORACLE = address(0xba5e);
    address internal constant ARB_ROLLUP = address(0xa4b1);
    bytes32 internal constant EMPTY_CODE_HASH =
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    function setUp() public virtual override {
        super.setUp();
        l1Oracle = new MockL1StateOracle();
        prover = new HomeChainProver(address(l1Oracle), HOME_KEYSTORE, address(this));

        prover.setChainProver(1, new L1ChainProver());
        prover.setChainProver(10, new OpStackChainProver(OP_OUTPUT_ORACLE));
        prover.setChainProver(8453, new OpStackChainProver(BASE_OUTPUT_ORACLE));
        prover.setChainProver(42161, new ArbitrumChainProver(ARB_ROLLUP));

        auth = new HomeChainAuthenticator(address(prover));
    }

    // ── Slot derivation + packing validated against the LIVE Keystore ──

    /// @dev Authorize a real explicit actor on the local Keystore, then read its raw slot via {StateProofLib}'s
    ///      derivation and decode it — proving the slot math and the ActorConfig packing match the deployed code.
    function test_slotAndDecode_matchLiveKeystore(uint256 ownerSeed, uint256 actorSeed, uint16 scopeSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));
        uint16 scope = uint16(bound(uint256(scopeSeed), 0, type(uint16).max)) & ~Scopes.POLICY;

        (address account,) = _createK1Account(ownerPk);
        bytes32 actorId = ActorId.fromAddress(vm.addr(actorPk));
        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), scope);

        bytes32 slot = StateProofLib.actorConfigSlot(actorId, account);
        uint256 word = uint256(vm.load(address(keystore), slot));
        (address authr, uint48 expiry, uint16 gotScope) = StateProofLib.decodeActorConfig(word);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(authr, cfg.authenticator, "authenticator");
        assertEq(uint256(expiry), uint256(cfg.expiry), "expiry");
        assertEq(uint256(gotScope), uint256(cfg.scope), "scope");
        assertEq(authr, address(k1Authenticator));
    }

    // ── L1 home (no recursion) ──

    function test_proveActorConfig_l1(bytes32 actorId, address homeAccount, uint16 scope) public {
        (bytes32 storageRoot, bytes[] memory storageProof) = _configLeaf(actorId, homeAccount, address(0xABCD), scope);
        (bytes32 l1StateRoot, bytes[] memory keystoreAccountProof) = _accountLeaf(HOME_KEYSTORE, storageRoot);
        l1Oracle.setStateRoot(l1StateRoot);

        bytes memory proof = _envelope(abi.encode(keystoreAccountProof), storageProof);
        (address authr,, uint16 gotScope) = prover.proveActorConfig(1, homeAccount, actorId, proof);
        assertEq(authr, address(0xABCD));
        assertEq(uint256(gotScope), uint256(scope));
    }

    // ── OP-stack home (Optimism / Base): recursive output-root → L2 state ──

    function test_proveActorConfig_opStack(bytes32 actorId, address homeAccount, uint16 scope) public {
        _runOpStack(10, OP_OUTPUT_ORACLE, actorId, homeAccount, scope);
        _runOpStack(8453, BASE_OUTPUT_ORACLE, actorId, homeAccount, scope);
    }

    function _runOpStack(uint256 chainId, address oracle, bytes32 actorId, address homeAccount, uint16 scope)
        internal
    {
        (bytes32 keystoreStorageRoot, bytes[] memory storageProof) =
            _configLeaf(actorId, homeAccount, address(0xABCD), scope);
        (bytes32 l2StateRoot, bytes[] memory keystoreAccountProof) = _accountLeaf(HOME_KEYSTORE, keystoreStorageRoot);

        bytes32 version = bytes32(uint256(0));
        bytes32 msgPasser = keccak256("msgPasser");
        bytes32 l2BlockHash = keccak256("l2Block");
        bytes32 outputRoot = StateProofLib.opOutputRoot(version, l2StateRoot, msgPasser, l2BlockHash);

        bytes32 outputRootSlot = bytes32(uint256(42));
        (bytes32 oracleStorageRoot, bytes[] memory oracleStorageProof) = _wordLeaf(outputRootSlot, uint256(outputRoot));
        (bytes32 l1StateRoot, bytes[] memory oracleAccountProof) = _accountLeaf(oracle, oracleStorageRoot);
        l1Oracle.setStateRoot(l1StateRoot);

        bytes memory chainProof = abi.encode(
            oracleAccountProof,
            outputRootSlot,
            oracleStorageProof,
            version,
            l2StateRoot,
            msgPasser,
            l2BlockHash,
            keystoreAccountProof
        );
        (address authr,, uint16 gotScope) = prover.proveActorConfig(chainId, homeAccount, actorId, _envelope(chainProof, storageProof));
        assertEq(authr, address(0xABCD));
        assertEq(uint256(gotScope), uint256(scope));
    }

    // ── Arbitrum home: recursive confirmData → L2 header → L2 state ──

    function test_proveActorConfig_arbitrum(bytes32 actorId, address homeAccount, uint16 scope) public {
        (bytes32 keystoreStorageRoot, bytes[] memory storageProof) =
            _configLeaf(actorId, homeAccount, address(0xABCD), scope);
        (bytes32 l2StateRoot, bytes[] memory keystoreAccountProof) = _accountLeaf(HOME_KEYSTORE, keystoreStorageRoot);

        bytes memory l2Header = _header(l2StateRoot);
        bytes32 l2BlockHash = keccak256(l2Header);
        bytes32 sendRoot = keccak256("sendRoot");
        bytes32 confirmData = StateProofLib.arbitrumConfirmData(l2BlockHash, sendRoot);

        bytes32 confirmDataSlot = bytes32(uint256(7));
        (bytes32 rollupStorageRoot, bytes[] memory rollupStorageProof) = _wordLeaf(confirmDataSlot, uint256(confirmData));
        (bytes32 l1StateRoot, bytes[] memory rollupAccountProof) = _accountLeaf(ARB_ROLLUP, rollupStorageRoot);
        l1Oracle.setStateRoot(l1StateRoot);

        bytes memory chainProof =
            abi.encode(rollupAccountProof, confirmDataSlot, rollupStorageProof, sendRoot, l2Header, keystoreAccountProof);
        (address authr,, uint16 gotScope) =
            prover.proveActorConfig(42161, homeAccount, actorId, _envelope(chainProof, storageProof));
        assertEq(authr, address(0xABCD));
        assertEq(uint256(gotScope), uint256(scope));
    }

    // ── Failure surfaces ──

    function test_proveActorConfig_revert_unknownChain(bytes32 actorId, address homeAccount) public {
        vm.expectRevert(abi.encodeWithSelector(HomeChainProver.UnknownHomeChain.selector, uint256(999)));
        prover.proveActorConfig(999, homeAccount, actorId, _envelope(abi.encode(new bytes[](0)), new bytes[](0)));
    }

    function test_opStack_revert_outputRootMismatch(bytes32 actorId, address homeAccount) public {
        (bytes32 keystoreStorageRoot, bytes[] memory storageProof) = _configLeaf(actorId, homeAccount, address(0xABCD), 0);
        (bytes32 l2StateRoot, bytes[] memory keystoreAccountProof) = _accountLeaf(HOME_KEYSTORE, keystoreStorageRoot);

        // Store an output root that does NOT match the preimage.
        bytes32 outputRootSlot = bytes32(uint256(42));
        (bytes32 oracleStorageRoot, bytes[] memory oracleStorageProof) =
            _wordLeaf(outputRootSlot, uint256(keccak256("wrong")));
        (bytes32 l1StateRoot, bytes[] memory oracleAccountProof) = _accountLeaf(OP_OUTPUT_ORACLE, oracleStorageRoot);
        l1Oracle.setStateRoot(l1StateRoot);

        bytes memory chainProof = abi.encode(
            oracleAccountProof,
            outputRootSlot,
            oracleStorageProof,
            bytes32(0),
            l2StateRoot,
            keccak256("msgPasser"),
            keccak256("l2Block"),
            keystoreAccountProof
        );
        vm.expectRevert(OpStackChainProver.OutputRootMismatch.selector);
        prover.proveActorConfig(10, homeAccount, actorId, _envelope(chainProof, storageProof));
    }

    // ── Local = Base: real L1BlockStateOracle (only the L1Block predeploy is mocked), home = OP ──

    /// @dev The full "Base(local) → OP(home)" stack: derive the L1 state root from an RLP L1 header verified against
    ///      the `L1Block` predeploy's committed blockhash, then recurse L1-committed output root → L2 state → config.
    function test_baseLocal_opHome_throughL1BlockPredeploy(bytes32 actorId, address homeAccount, uint16 scope) public {
        // Home (OP) proof, terminating in an L1 state root we then anchor via the predeploy.
        (bytes32 keystoreStorageRoot, bytes[] memory storageProof) =
            _configLeaf(actorId, homeAccount, address(0xABCD), scope);
        (bytes32 l2StateRoot, bytes[] memory keystoreAccountProof) = _accountLeaf(HOME_KEYSTORE, keystoreStorageRoot);

        bytes32 version = bytes32(uint256(0));
        bytes32 msgPasser = keccak256("msgPasser");
        bytes32 l2BlockHash = keccak256("l2Block");
        bytes32 outputRoot = StateProofLib.opOutputRoot(version, l2StateRoot, msgPasser, l2BlockHash);

        bytes32 outputRootSlot = bytes32(uint256(42));
        (bytes32 oracleStorageRoot, bytes[] memory oracleStorageProof) = _wordLeaf(outputRootSlot, uint256(outputRoot));
        (bytes32 l1StateRoot, bytes[] memory oracleAccountProof) = _accountLeaf(OP_OUTPUT_ORACLE, oracleStorageRoot);

        // Local anchor: an RLP L1 header carrying l1StateRoot at field 3, committed by the predeploy's blockhash.
        bytes memory l1Header = _header(l1StateRoot);
        bytes32 l1BlockHash = keccak256(l1Header);

        L1BlockStateOracle baseOracle = new L1BlockStateOracle();
        HomeChainProver baseProver = new HomeChainProver(address(baseOracle), HOME_KEYSTORE, address(this));
        baseProver.setChainProver(10, new OpStackChainProver(OP_OUTPUT_ORACLE));
        vm.mockCall(
            address(baseOracle.L1_BLOCK()), abi.encodeWithSelector(IL1Block.hash.selector), abi.encode(l1BlockHash)
        );

        bytes memory chainProof = abi.encode(
            oracleAccountProof,
            outputRootSlot,
            oracleStorageProof,
            version,
            l2StateRoot,
            msgPasser,
            l2BlockHash,
            keystoreAccountProof
        );
        bytes memory proof =
            abi.encode(HomeChainProver.Proof({l1HeaderProof: l1Header, chainProof: chainProof, storageProof: storageProof}));

        (address authr,, uint16 gotScope) = baseProver.proveActorConfig(10, homeAccount, actorId, proof);
        assertEq(authr, address(0xABCD));
        assertEq(uint256(gotScope), uint256(scope));
    }

    /// @dev A header that does not hash to the predeploy's committed blockhash must be rejected by the oracle.
    function test_baseLocal_revert_staleL1Header(bytes32 actorId, address homeAccount) public {
        L1BlockStateOracle baseOracle = new L1BlockStateOracle();
        HomeChainProver baseProver = new HomeChainProver(address(baseOracle), HOME_KEYSTORE, address(this));
        baseProver.setChainProver(1, new L1ChainProver());
        vm.mockCall(
            address(baseOracle.L1_BLOCK()),
            abi.encodeWithSelector(IL1Block.hash.selector),
            abi.encode(keccak256("some other L1 block"))
        );

        bytes memory proof = abi.encode(
            HomeChainProver.Proof({
                l1HeaderProof: _header(bytes32(uint256(1))),
                chainProof: abi.encode(new bytes[](0)),
                storageProof: new bytes[](0)
            })
        );
        vm.expectRevert(L1BlockStateOracle.StaleOrInvalidL1Header.selector);
        baseProver.proveActorConfig(1, homeAccount, actorId, proof);
    }

    // ── End-to-end: HomeChainAuthenticator → HomeChainProver → Keystore (L1 home, K1 admin) ──

    function test_endToEnd_l1AdminThroughAuthenticator(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address homeAccount = address(0xF00D);
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));

        // Home config: signer is a K1 admin (authenticator == K1 sentinel address(1), scope 0) of homeAccount on L1.
        (bytes32 storageRoot, bytes[] memory storageProof) =
            _configLeaf(signerActor, homeAccount, k1Authenticator, 0);
        (bytes32 l1StateRoot, bytes[] memory keystoreAccountProof) = _accountLeaf(HOME_KEYSTORE, storageRoot);
        l1Oracle.setStateRoot(l1StateRoot);
        bytes memory proof = _envelope(abi.encode(keystoreAccountProof), storageProof);

        // Register the home actorId as an admin on a fresh L2 account, bound to the authenticator.
        bytes32 actorId = auth.homeActorId(1, homeAccount);
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({actorId: actorId, authenticator: address(auth), scope: 0, policyData: ""});
        address l2Account =
            keystore.createAccount(bytes32(uint256(11)), _computeERC1167Bytecode(defaultAccountImplementation), actors);

        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(pk, hash));
        bytes memory data = auth.encode(1, homeAccount, nested, proof);

        (bytes32 got, uint16 scope) = keystore.authenticateActor(l2Account, hash, abi.encodePacked(address(auth), data));
        assertEq(got, actorId);
        assertEq(scope, 0);
    }

    // ── Fixture builders (real single-leaf MPT tries) ──

    /// @dev Config storage leaf for `_actors[actorId][account].config` holding (authenticator, expiry 0, scope).
    function _configLeaf(bytes32 actorId, address account, address authenticator, uint16 scope)
        internal
        pure
        returns (bytes32 root, bytes[] memory proof)
    {
        uint256 word = uint256(uint160(authenticator)) | (uint256(scope) << 208);
        bytes32 slot = StateProofLib.actorConfigSlot(actorId, account);
        return _wordLeaf(slot, word);
    }

    /// @dev Storage leaf: slot => word (as the trie value RLP(word)).
    function _wordLeaf(bytes32 slot, uint256 word) internal pure returns (bytes32 root, bytes[] memory proof) {
        bytes32 pathKey = keccak256(abi.encode(slot));
        return _leaf(pathKey, RLP.encode(word));
    }

    /// @dev Account leaf: address => RLP([nonce, balance, storageRoot, codeHash]).
    function _accountLeaf(address account, bytes32 storageRoot)
        internal
        pure
        returns (bytes32 root, bytes[] memory proof)
    {
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(uint256(0));
        fields[1] = RLP.encode(uint256(0));
        fields[2] = RLP.encode(storageRoot);
        fields[3] = RLP.encode(EMPTY_CODE_HASH);
        bytes32 pathKey = keccak256(abi.encodePacked(account));
        return _leaf(pathKey, RLP.encode(fields));
    }

    /// @dev Minimal RLP block header with `stateRoot` at field index 3.
    function _header(bytes32 stateRoot) internal pure returns (bytes memory) {
        bytes[] memory fields = new bytes[](4);
        fields[0] = RLP.encode(bytes32(0));
        fields[1] = RLP.encode(bytes32(0));
        fields[2] = RLP.encode(bytes32(0));
        fields[3] = RLP.encode(stateRoot);
        return RLP.encode(fields);
    }

    /// @dev Builds a single-leaf secure-trie: root + 1-node proof for (pathKey => trieValue).
    function _leaf(bytes32 pathKey, bytes memory trieValue) internal pure returns (bytes32 root, bytes[] memory proof) {
        bytes memory compactPath = abi.encodePacked(bytes1(0x20), pathKey); // leaf, even-length nibbles
        bytes[] memory node = new bytes[](2);
        node[0] = RLP.encode(compactPath);
        node[1] = RLP.encode(trieValue);
        bytes memory encoded = RLP.encode(node);
        proof = new bytes[](1);
        proof[0] = encoded;
        root = keccak256(encoded);
    }

    function _envelope(bytes memory chainProof, bytes[] memory storageProof) internal pure returns (bytes memory) {
        return abi.encode(HomeChainProver.Proof({l1HeaderProof: "", chainProof: chainProof, storageProof: storageProof}));
    }
}
