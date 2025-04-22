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
import {Permit2TestHelper} from "./Permit2TestHelper.sol";

contract TychoRouterExposed is TychoRouter {
    constructor(address _permit2, address weth) TychoRouter(_permit2, weth) {}

    function wrapETH(uint256 amount) external payable {
        return _wrapETH(amount);
    }

    function unwrapETH(uint256 amount) external {
        return _unwrapETH(amount);
    }

    function exposedSplitSwap(
        uint256 amountIn,
        uint256 nTokens,
        bytes calldata swaps
    ) external returns (uint256) {
        return _splitSwap(amountIn, nTokens, swaps);
    }

    function exposedSequentialSwap(uint256 amountIn, bytes calldata swaps)
        external
        returns (uint256)
    {
        return _sequentialSwap(amountIn, swaps);
    }
}

contract TychoRouterTestSetup is Constants, Permit2TestHelper {
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
        uint256 forkBlock = 22082754;
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
        usv2Executor =
            new UniswapV2Executor(factoryV2, initCodeV2, PERMIT2_ADDRESS);
        usv3Executor =
            new UniswapV3Executor(factoryV3, initCodeV3, PERMIT2_ADDRESS);
        usv4Executor = new UniswapV4Executor(poolManager, PERMIT2_ADDRESS);
        pancakev3Executor = new UniswapV3Executor(
            factoryPancakeV3, initCodePancakeV3, PERMIT2_ADDRESS
        );
        balancerv2Executor = new BalancerV2Executor(PERMIT2_ADDRESS);
        ekuboExecutor = new EkuboExecutor(ekuboCore, PERMIT2_ADDRESS);
        curveExecutor = new CurveExecutor(ETH_ADDR_FOR_CURVE, PERMIT2_ADDRESS);

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

    function encodeSingleSwap(address executor, bytes memory protocolData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(executor, protocolData);
    }

    function encodeSequentialSwap(address executor, bytes memory protocolData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(executor, protocolData);
    }

    function encodeSplitSwap(
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
        bool zero2one,
        TokenTransfer.TransferType transferType
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(tokenIn, target, receiver, zero2one, transferType);
    }

    function encodeUniswapV3Swap(
        address tokenIn,
        address tokenOut,
        address receiver,
        address target,
        bool zero2one,
        TokenTransfer.TransferType transferType
    ) internal view returns (bytes memory) {
        IUniswapV3Pool pool = IUniswapV3Pool(target);
        return abi.encodePacked(
            tokenIn,
            tokenOut,
            pool.fee(),
            receiver,
            target,
            zero2one,
            transferType
        );
    }
}
