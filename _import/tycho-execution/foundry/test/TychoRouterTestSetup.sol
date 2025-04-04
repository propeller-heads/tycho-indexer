// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../src/executors/BalancerV2Executor.sol";
import "../src/executors/CurveExecutor.sol";
import "../src/executors/EkuboExecutor.sol";
import "../src/executors/UniswapV2Executor.sol";
import "../src/executors/UniswapV3Executor.sol";
import "../src/executors/UniswapV4Executor.sol";
import "./Constants.sol";
import "./mock/MockERC20.sol";
import "@src/TychoRouter.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {WETH} from "../lib/permit2/lib/solmate/src/tokens/WETH.sol";

contract TychoRouterExposed is TychoRouter {
    constructor(address _permit2, address weth) TychoRouter(_permit2, weth) {}

    function wrapETH(uint256 amount) external payable {
        return _wrapETH(amount);
    }

    function unwrapETH(uint256 amount) external {
        return _unwrapETH(amount);
    }

    function exposedSwap(
        uint256 amountIn,
        uint256 nTokens,
        bytes calldata swaps
    ) external returns (uint256) {
        return _swap(amountIn, nTokens, swaps);
    }
}

contract TychoRouterTestSetup is Test, Constants {
    TychoRouterExposed tychoRouter;
    address tychoRouterAddr;
    UniswapV2Executor public usv2Executor;
    UniswapV3Executor public usv3Executor;
    UniswapV3Executor public pancakev3Executor;
    UniswapV4Executor public usv4Executor;
    BalancerV2Executor public balancerv2Executor;
    EkuboExecutor public ekuboExecutor;
    CurveExecutor public curveExecutor;
    MockERC20[] tokens;

    function setUp() public {
        uint256 forkBlock = 21817316;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        vm.startPrank(ADMIN);
        tychoRouter = deployRouter();
        deployDummyContract();
        vm.stopPrank();

        address[] memory executors = deployExecutors();
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setExecutors(executors);
        vm.stopPrank();

        vm.startPrank(BOB);
        tokens.push(new MockERC20("Token A", "A"));
        tokens.push(new MockERC20("Token B", "B"));
        tokens.push(new MockERC20("Token C", "C"));
        vm.stopPrank();
    }

    function deployRouter() public returns (TychoRouterExposed) {
        tychoRouter = new TychoRouterExposed(PERMIT2_ADDRESS, WETH_ADDR);
        tychoRouterAddr = address(tychoRouter);
        tychoRouter.grantRole(keccak256("FUND_RESCUER_ROLE"), FUND_RESCUER);
        tychoRouter.grantRole(keccak256("FEE_SETTER_ROLE"), FEE_SETTER);
        tychoRouter.grantRole(keccak256("PAUSER_ROLE"), PAUSER);
        tychoRouter.grantRole(keccak256("UNPAUSER_ROLE"), UNPAUSER);
        tychoRouter.grantRole(
            keccak256("EXECUTOR_SETTER_ROLE"), EXECUTOR_SETTER
        );
        return tychoRouter;
    }

    function deployExecutors() public returns (address[] memory) {
        address factoryV2 = USV2_FACTORY_ETHEREUM;
        address factoryV3 = USV3_FACTORY_ETHEREUM;
        address factoryPancakeV3 = PANCAKESWAPV3_DEPLOYER_ETHEREUM;
        bytes32 initCodeV2 = USV2_POOL_CODE_INIT_HASH;
        bytes32 initCodeV3 = USV3_POOL_CODE_INIT_HASH;
        bytes32 initCodePancakeV3 = PANCAKEV3_POOL_CODE_INIT_HASH;
        address poolManagerAddress = 0x000000000004444c5dc75cB358380D2e3dE08A90;
        address ekuboCore = 0xe0e0e08A6A4b9Dc7bD67BCB7aadE5cF48157d444;

        IPoolManager poolManager = IPoolManager(poolManagerAddress);
        usv2Executor = new UniswapV2Executor(factoryV2, initCodeV2);
        usv3Executor = new UniswapV3Executor(factoryV3, initCodeV3);
        usv4Executor = new UniswapV4Executor(poolManager);
        pancakev3Executor =
            new UniswapV3Executor(factoryPancakeV3, initCodePancakeV3);
        balancerv2Executor = new BalancerV2Executor();
        ekuboExecutor = new EkuboExecutor(ekuboCore);
        curveExecutor = new CurveExecutor(ETH_ADDR);

        address[] memory executors = new address[](7);
        executors[0] = address(usv2Executor);
        executors[1] = address(usv3Executor);
        executors[2] = address(pancakev3Executor);
        executors[3] = address(usv4Executor);
        executors[4] = address(balancerv2Executor);
        executors[5] = address(ekuboExecutor);
        executors[6] = address(curveExecutor);
        return executors;
    }

    /**
     * @dev Mints tokens to the given address
     * @param amount The amount of tokens to mint
     * @param to The address to mint tokens to
     */
    function mintTokens(uint256 amount, address to) internal {
        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            tokens[i].mint(to, amount);
        }
    }

    /**
     * @dev Handles the Permit2 approval process for Alice, allowing the TychoRouter contract
     *      to spend `amount_in` of `tokenIn` on her behalf.
     *
     * This function approves the Permit2 contract to transfer the specified token amount
     * and constructs a `PermitSingle` struct for the approval. It also generates a valid
     * EIP-712 signature for the approval using Alice's private key.
     *
     * @param tokenIn The address of the token being approved.
     * @param amount_in The amount of tokens to approve for transfer.
     * @return permitSingle The `PermitSingle` struct containing the approval details.
     * @return signature The EIP-712 signature for the approval.
     */
    function handlePermit2Approval(address tokenIn, uint256 amount_in)
        internal
        returns (IAllowanceTransfer.PermitSingle memory, bytes memory)
    {
        IERC20(tokenIn).approve(PERMIT2_ADDRESS, amount_in);
        IAllowanceTransfer.PermitSingle memory permitSingle = IAllowanceTransfer
            .PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: tokenIn,
                amount: uint160(amount_in),
                expiration: uint48(block.timestamp + 1 days),
                nonce: 0
            }),
            spender: tychoRouterAddr,
            sigDeadline: block.timestamp + 1 days
        });

        bytes memory signature = signPermit2(permitSingle, ALICE_PK);
        return (permitSingle, signature);
    }

    /**
     * @dev Signs a Permit2 `PermitSingle` struct with the given private key.
     * @param permit The `PermitSingle` struct to sign.
     * @param privateKey The private key of the signer.
     * @return The signature as a `bytes` array.
     */
    function signPermit2(
        IAllowanceTransfer.PermitSingle memory permit,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 _PERMIT_DETAILS_TYPEHASH = keccak256(
            "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
        );
        bytes32 _PERMIT_SINGLE_TYPEHASH = keccak256(
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
                ),
                keccak256("Permit2"),
                block.chainid,
                PERMIT2_ADDRESS
            )
        );
        bytes32 detailsHash =
            keccak256(abi.encode(_PERMIT_DETAILS_TYPEHASH, permit.details));
        bytes32 permitHash = keccak256(
            abi.encode(
                _PERMIT_SINGLE_TYPEHASH,
                detailsHash,
                permit.spender,
                permit.sigDeadline
            )
        );

        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, permitHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function pleEncode(bytes[] memory data)
        public
        pure
        returns (bytes memory encoded)
    {
        for (uint256 i = 0; i < data.length; i++) {
            encoded = bytes.concat(
                encoded,
                abi.encodePacked(bytes2(uint16(data[i].length)), data[i])
            );
        }
    }

    function encodeSwap(
        uint8 tokenInIndex,
        uint8 tokenOutIndex,
        uint24 split,
        address executor,
        bytes memory protocolData
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            tokenInIndex, tokenOutIndex, split, executor, protocolData
        );
    }

    function encodeUniswapV2Swap(
        address tokenIn,
        address target,
        address receiver,
        bool zero2one
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(tokenIn, target, receiver, zero2one);
    }

    function encodeUniswapV3Swap(
        address tokenIn,
        address tokenOut,
        address receiver,
        address target,
        bool zero2one
    ) internal view returns (bytes memory) {
        IUniswapV3Pool pool = IUniswapV3Pool(target);
        return abi.encodePacked(
            tokenIn, tokenOut, pool.fee(), receiver, target, zero2one
        );
    }
}
