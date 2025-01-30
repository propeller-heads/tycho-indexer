// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../src/executors/UniswapV2Executor.sol";
import "./Constants.sol";
import "./mock/MockERC20.sol";
import "@src/TychoRouter.sol";
import {WETH} from "../lib/permit2/lib/solmate/src/tokens/WETH.sol";

contract TychoRouterExposed is TychoRouter {
    constructor(address _permit2, address weth, address usv3Factory)
        TychoRouter(_permit2, weth, usv3Factory)
    {}

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
    address permit2Address = address(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    UniswapV2Executor public usv2Executor;
    MockERC20[] tokens;

    function setUp() public {
        uint256 forkBlock = 21000000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        vm.startPrank(ADMIN);
        tychoRouter =
            new TychoRouterExposed(permit2Address, WETH_ADDR, address(1));
        tychoRouterAddr = address(tychoRouter);
        tychoRouter.grantRole(keccak256("FUND_RESCUER_ROLE"), FUND_RESCUER);
        tychoRouter.grantRole(keccak256("FEE_SETTER_ROLE"), FEE_SETTER);
        tychoRouter.grantRole(keccak256("PAUSER_ROLE"), PAUSER);
        tychoRouter.grantRole(keccak256("UNPAUSER_ROLE"), UNPAUSER);
        tychoRouter.grantRole(
            keccak256("EXECUTOR_SETTER_ROLE"), EXECUTOR_SETTER
        );
        deployDummyContract();
        vm.stopPrank();

        usv2Executor = new UniswapV2Executor();
        vm.startPrank(EXECUTOR_SETTER);
        address[] memory executors = new address[](1);
        executors[0] = address(usv2Executor);
        tychoRouter.batchSetExecutor(executors);
        vm.stopPrank();

        vm.startPrank(BOB);
        tokens.push(new MockERC20("Token A", "A"));
        tokens.push(new MockERC20("Token B", "B"));
        tokens.push(new MockERC20("Token C", "C"));
        vm.stopPrank();
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
        IERC20(tokenIn).approve(permit2Address, amount_in);
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
                permit2Address
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
        bytes4 selector,
        bytes memory protocolData
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            tokenInIndex, tokenOutIndex, split, executor, selector, protocolData
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
}
