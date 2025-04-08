// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV2Executor.sol";
import "@src/executors/ExecutorTransferMethods.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";

contract UniswapV2ExecutorExposed is UniswapV2Executor {
    constructor(address _factory, bytes32 _initCode, address _permit2)
        UniswapV2Executor(_factory, _initCode, _permit2)
    {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IERC20 inToken,
            address target,
            address receiver,
            bool zeroForOne,
            TransferMethod method
        )
    {
        return _decodeData(data);
    }

    function getAmountOut(address target, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (uint256 amount)
    {
        return _getAmountOut(target, amountIn, zeroForOne);
    }

    function verifyPairAddress(address target) external view {
        _verifyPairAddress(target);
    }
}

contract FakeUniswapV2Pool {
    address public token0;
    address public token1;

    constructor(address _tokenA, address _tokenB) {
        token0 = _tokenA < _tokenB ? _tokenA : _tokenB;
        token1 = _tokenA < _tokenB ? _tokenB : _tokenA;
    }
}

contract UniswapV2ExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    UniswapV2ExecutorExposed uniswapV2Exposed;
    UniswapV2ExecutorExposed sushiswapV2Exposed;
    UniswapV2ExecutorExposed pancakeswapV2Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    IAllowanceTransfer permit2;

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV2Exposed = new UniswapV2ExecutorExposed(
            USV2_FACTORY_ETHEREUM, USV2_POOL_CODE_INIT_HASH, PERMIT2_ADDRESS
        );
        sushiswapV2Exposed = new UniswapV2ExecutorExposed(
            SUSHISWAPV2_FACTORY_ETHEREUM,
            SUSHIV2_POOL_CODE_INIT_HASH,
            PERMIT2_ADDRESS
        );
        pancakeswapV2Exposed = new UniswapV2ExecutorExposed(
            PANCAKESWAPV2_FACTORY_ETHEREUM,
            PANCAKEV2_POOL_CODE_INIT_HASH,
            PERMIT2_ADDRESS
        );
        permit2 = IAllowanceTransfer(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            address(2),
            address(3),
            false,
            ExecutorTransferMethods.TransferMethod.TRANSFER
        );

        (
            IERC20 tokenIn,
            address target,
            address receiver,
            bool zeroForOne,
            ExecutorTransferMethods.TransferMethod method
        ) = uniswapV2Exposed.decodeParams(params);

        assertEq(address(tokenIn), WETH_ADDR);
        assertEq(target, address(2));
        assertEq(receiver, address(3));
        assertEq(zeroForOne, false);
        assertEq(
            uint8(ExecutorTransferMethods.TransferMethod.TRANSFER),
            uint8(method)
        );
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(WETH_ADDR, address(2), address(3));

        vm.expectRevert(UniswapV2Executor__InvalidDataLength.selector);
        uniswapV2Exposed.decodeParams(invalidParams);
    }

    function testVerifyPairAddress() public view {
        uniswapV2Exposed.verifyPairAddress(WETH_DAI_POOL);
    }

    function testVerifyPairAddressSushi() public view {
        sushiswapV2Exposed.verifyPairAddress(SUSHISWAP_WBTC_WETH_POOL);
    }

    function testVerifyPairAddressPancake() public view {
        pancakeswapV2Exposed.verifyPairAddress(PANCAKESWAP_WBTC_WETH_POOL);
    }

    function testInvalidTarget() public {
        address fakePool = address(new FakeUniswapV2Pool(WETH_ADDR, DAI_ADDR));
        vm.expectRevert(UniswapV2Executor__InvalidTarget.selector);
        uniswapV2Exposed.verifyPairAddress(fakePool);
    }

    function testAmountOut() public view {
        uint256 amountOut =
            uniswapV2Exposed.getAmountOut(WETH_DAI_POOL, 10 ** 18, false);
        uint256 expAmountOut = 1847751195973566072891;
        assertEq(amountOut, expAmountOut);
    }

    // triggers a uint112 overflow on purpose
    function testAmountOutInt112Overflow() public view {
        address target = 0x0B9f5cEf1EE41f8CCCaA8c3b4c922Ab406c980CC;
        uint256 amountIn = 83638098812630667483959471576;

        uint256 amountOut =
            uniswapV2Exposed.getAmountOut(target, amountIn, true);

        assertGe(amountOut, 0);
    }

    function testSwapWithTransfer() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            BOB,
            zeroForOne,
            uint8(ExecutorTransferMethods.TransferMethod.TRANSFER)
        );

        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testSwapWithTransferFrom() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            BOB,
            zeroForOne,
            uint8(ExecutorTransferMethods.TransferMethod.TRANSFERFROM)
        );

        deal(WETH_ADDR, address(this), amountIn);
        IERC20(WETH_ADDR).approve(address(uniswapV2Exposed), amountIn);

        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    // TODO generalize these next two methods - don't reuse from TychoRouterTestSetup
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
            spender: address(uniswapV2Exposed),
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


    function testSwapWithPermit2TransferFrom() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            ALICE,
            zeroForOne,
            uint8(ExecutorTransferMethods.TransferMethod.TRANSFERPERMIT2)
        );


        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        // Assume the permit2.approve method will be called from the TychoRouter
        // Replicate this secnario in this test.
        permit2.permit(ALICE, permitSingle, signature);

        uniswapV2Exposed.swap(amountIn, protocolData);
        vm.stopPrank();

        uint256 finalBalance = DAI.balanceOf(ALICE);
        assertGe(finalBalance, amountOut);
    }

    function testSwapNoTransfer() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            BOB,
            zeroForOne,
            uint8(ExecutorTransferMethods.TransferMethod.NONE)
        );

        deal(WETH_ADDR, address(this), amountIn);
        IERC20(WETH_ADDR).transfer(address(WETH_DAI_POOL), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testDecodeIntegration() public view {
        // Generated by the ExecutorStrategyEncoder - test_executor_strategy_encode
        bytes memory protocolData =
            hex"c02aaa39b223fe8d0a0e5c4f27ead9083c756cc288e6a0c2ddd26feeb64f039a2c41296fcb3f564000000000000000000000000000000000000000010000";

        (
            IERC20 tokenIn,
            address target,
            address receiver,
            bool zeroForOne,
            ExecutorTransferMethods.TransferMethod method
        ) = uniswapV2Exposed.decodeParams(protocolData);

        assertEq(address(tokenIn), WETH_ADDR);
        assertEq(target, 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640);
        assertEq(receiver, 0x0000000000000000000000000000000000000001);
        assertEq(zeroForOne, false);
        // TRANSFER = 0
        assertEq(0, uint8(method));
    }

    function testSwapIntegration() public {
        // Generated by the ExecutorStrategyEncoder - test_executor_strategy_encode
        bytes memory protocolData =
            hex"c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb111d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000";
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testSwapFailureInvalidTarget() public {
        uint256 amountIn = 10 ** 18;
        bool zeroForOne = false;
        address fakePool = address(new FakeUniswapV2Pool(WETH_ADDR, DAI_ADDR));
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            fakePool,
            BOB,
            zeroForOne,
            uint8(ExecutorTransferMethods.TransferMethod.TRANSFER)
        );

        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        vm.expectRevert(UniswapV2Executor__InvalidTarget.selector);
        uniswapV2Exposed.swap(amountIn, protocolData);
    }

    // Base Network Tests
    // Make sure to set the RPC_URL to base network
    function testSwapBaseNetwork() public {
        vm.skip(true);
        vm.rollFork(26857267);
        uint256 amountIn = 10 * 10 ** 6;
        bool zeroForOne = true;
        bytes memory protocolData = abi.encodePacked(
            BASE_USDC,
            USDC_MAG7_POOL,
            BOB,
            zeroForOne,
            uint8(ExecutorTransferMethods.TransferMethod.TRANSFER)
        );

        deal(BASE_USDC, address(uniswapV2Exposed), amountIn);

        uniswapV2Exposed.swap(amountIn, protocolData);

        assertEq(IERC20(BASE_MAG7).balanceOf(BOB), 1379830606);
    }
}
