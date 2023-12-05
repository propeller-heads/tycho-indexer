// SPDX-License-Identifier: AGPL-3.0-or-later
pragma experimental ABIEncoderV2;
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

uint256 constant RESERVE_LIMIT_FACTOR = 10; // TODO why is the factor so high?
uint256 constant SWAP_DEADLINE_SEC = 1000;

contract BalancerV2SwapAdapter is ISwapAdapter {
    IVault immutable vault;

    constructor(address payable vault_) {
        vault = IVault(vault_);
    }

    function priceSingle(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 sellAmount
    ) public returns (Fraction memory calculatedPrice) {
        IVault.BatchSwapStep[] memory swapSteps = new IVault.BatchSwapStep[](1);
        swapSteps[0] = IVault.BatchSwapStep({
            poolId: pairId,
            assetInIndex: 0,
            assetOutIndex: 1,
            amount: sellAmount,
            userData: ""
        });
        address[] memory assets = new address[](2);
        assets[0] = address(sellToken);
        assets[1] = address(buyToken);
        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: msg.sender,
            fromInternalBalance: false,
            recipient: payable(msg.sender),
            toInternalBalance: false
        });

        // assetDeltas correspond to the assets array
        int256[] memory assetDeltas = new int256[](2);
        assetDeltas = vault.queryBatchSwap(
            IVault.SwapKind.GIVEN_IN, swapSteps, assets, funds
        );

        // TODO: the delta of buyToken is negative, so we need to flip the sign 
        calculatedPrice = Fraction(uint256(assetDeltas[1]), sellAmount);
    }

    function getSellAmount(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256 buyAmount
    ) public returns (uint256 sellAmount) {
        IVault.BatchSwapStep[] memory swapSteps = new IVault.BatchSwapStep[](1);
        swapSteps[0] = IVault.BatchSwapStep({
            poolId: pairId,
            assetInIndex: 0,
            assetOutIndex: 1,
            amount: buyAmount,
            userData: ""
        });
        address[] memory assets = new address[](2);
        assets[0] = address(sellToken);
        assets[1] = address(buyToken);
        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: msg.sender,
            fromInternalBalance: false,
            recipient: payable(msg.sender),
            toInternalBalance: false
        });

        // assetDeltas correspond to the assets array
        int256[] memory assetDeltas = new int256[](2);
        assetDeltas = vault.queryBatchSwap(
            IVault.SwapKind.GIVEN_OUT, swapSteps, assets, funds
        );

        sellAmount = uint256(assetDeltas[0]);
    }

    function priceBatch(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256[] memory specifiedAmounts
    ) external returns (Fraction[] memory calculatedPrices) {
        for (uint256 i = 0; i < specifiedAmounts.length; i++) {
            calculatedPrices[i] =
                priceSingle(pairId, sellToken, buyToken, specifiedAmounts[i]);
        }
    }

    function price(bytes32, IERC20, IERC20, uint256[] memory)
        external
        pure
        override
        returns (Fraction[] memory)
    {
        revert NotImplemented("BalancerV2SwapAdapter.price");
    }

    function swap(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external override returns (Trade memory trade) {
        uint256 sellAmount;
        IVault.SwapKind kind;
        uint256 limit; // TODO set this slippage limit properly
        if (side == OrderSide.Sell) {
            kind = IVault.SwapKind.GIVEN_IN;
            sellAmount = specifiedAmount;
            limit = 0;
        } else {
            kind = IVault.SwapKind.GIVEN_OUT;
            sellAmount = getSellAmount(pairId, sellToken, buyToken, specifiedAmount);
            limit = type(uint256).max;
        }

        sellToken.transferFrom(msg.sender, address(this), sellAmount);
        sellToken.approve(address(vault), sellAmount);

        uint256 gasBefore = gasleft();
        trade.calculatedAmount = vault.swap(
            IVault.SingleSwap({
                poolId: pairId,
                kind: kind,
                assetIn: address(sellToken),
                assetOut: address(buyToken),
                amount: specifiedAmount,
                userData: ""
            }),
            IVault.FundManagement({
                sender: address(this),
                fromInternalBalance: false,
                recipient: msg.sender,
                toInternalBalance: false
            }),
            limit,
            block.timestamp + SWAP_DEADLINE_SEC
        );
        trade.gasUsed = gasBefore - gasleft();
        trade.price = Fraction(0, 1); // Without the price function return 0.
    }

    function getLimits(bytes32 pairId, IERC20 sellToken, IERC20 buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        limits = new uint256[](2);
        (IERC20[] memory tokens, uint256[] memory balances,) =
            vault.getPoolTokens(pairId);

        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == sellToken) {
                limits[0] = balances[i] * RESERVE_LIMIT_FACTOR;
            }
            if (tokens[i] == buyToken) {
                limits[1] = balances[i] * RESERVE_LIMIT_FACTOR;
            }
        }
    }

    function getCapabilities(bytes32, IERC20, IERC20)
        external
        pure
        override
        returns (Capability[] memory capabilities)
    {
        capabilities = new Capability[](2);
        capabilities[0] = Capability.SellOrder;
        capabilities[1] = Capability.BuyOrder;
    }

    function getTokens(bytes32 pairId)
        external
        view
        override
        returns (IERC20[] memory tokens)
    {
        (tokens,,) = vault.getPoolTokens(pairId);
    }

    /// @dev Balancer V2 does not support enumerating pools, they have to be
    /// indexed off-chain.
    function getPoolIds(uint256, uint256)
        external
        pure
        override
        returns (bytes32[] memory)
    {
        revert NotImplemented("BalancerV2SwapAdapter.getPoolIds");
    }
}

interface IVault {
    struct BatchSwapStep {
        bytes32 poolId;
        uint256 assetInIndex;
        uint256 assetOutIndex;
        uint256 amount;
        bytes userData;
    }

    struct FundManagement {
        address sender;
        bool fromInternalBalance;
        address recipient;
        bool toInternalBalance;
    }

    struct ExitPoolRequest {
        address[] assets;
        uint256[] minAmountsOut;
        bytes userData;
        bool toInternalBalance;
    }

    struct JoinPoolRequest {
        address[] assets;
        uint256[] maxAmountsIn;
        bytes userData;
        bool fromInternalBalance;
    }

    struct PoolBalanceOp {
        SwapKind kind;
        bytes32 poolId;
        address token;
        uint256 amount;
    }

    struct UserBalanceOp {
        SwapKind kind;
        address asset;
        uint256 amount;
        address sender;
        address recipient;
    }

    struct SingleSwap {
        bytes32 poolId;
        SwapKind kind;
        address assetIn;
        address assetOut;
        uint256 amount;
        bytes userData;
    }

    event AuthorizerChanged(address indexed newAuthorizer);
    event ExternalBalanceTransfer(
        address indexed token,
        address indexed sender,
        address recipient,
        uint256 amount
    );
    event FlashLoan(
        address indexed recipient,
        address indexed token,
        uint256 amount,
        uint256 feeAmount
    );
    event InternalBalanceChanged(
        address indexed user, address indexed token, int256 delta
    );
    event PausedStateChanged(bool paused);
    event PoolBalanceChanged(
        bytes32 indexed poolId,
        address indexed liquidityProvider,
        address[] tokens,
        int256[] deltas,
        uint256[] protocolFeeAmounts
    );
    event PoolBalanceManaged(
        bytes32 indexed poolId,
        address indexed assetManager,
        address indexed token,
        int256 cashDelta,
        int256 managedDelta
    );
    event PoolRegistered(
        bytes32 indexed poolId,
        address indexed poolAddress,
        uint8 specialization
    );
    event RelayerApprovalChanged(
        address indexed relayer, address indexed sender, bool approved
    );
    event Swap(
        bytes32 indexed poolId,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut
    );
    event TokensDeregistered(bytes32 indexed poolId, address[] tokens);
    event TokensRegistered(
        bytes32 indexed poolId, address[] tokens, address[] assetManagers
    );

    function WETH() external view returns (address);

    function batchSwap(
        SwapKind kind,
        BatchSwapStep[] memory swaps,
        address[] memory assets,
        FundManagement memory funds,
        int256[] memory limits,
        uint256 deadline
    ) external payable returns (int256[] memory assetDeltas);

    function deregisterTokens(bytes32 poolId, address[] memory tokens)
        external;

    function exitPool(
        bytes32 poolId,
        address sender,
        address recipient,
        ExitPoolRequest memory request
    ) external;

    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;

    function getActionId(bytes4 selector) external view returns (bytes32);

    function getAuthorizer() external view returns (address);

    function getDomainSeparator() external view returns (bytes32);

    function getInternalBalance(address user, address[] memory tokens)
        external
        view
        returns (uint256[] memory balances);

    function getNextNonce(address user) external view returns (uint256);

    function getPausedState()
        external
        view
        returns (
            bool paused,
            uint256 pauseWindowEndTime,
            uint256 bufferPeriodEndTime
        );

    function getPool(bytes32 poolId) external view returns (address, uint8);

    function getPoolTokenInfo(bytes32 poolId, address token)
        external
        view
        returns (
            uint256 cash,
            uint256 managed,
            uint256 lastChangeBlock,
            address assetManager
        );

    function getProtocolFeesCollector() external view returns (address);

    function hasApprovedRelayer(address user, address relayer)
        external
        view
        returns (bool);

    function joinPool(
        bytes32 poolId,
        address sender,
        address recipient,
        JoinPoolRequest memory request
    ) external payable;

    function managePoolBalance(PoolBalanceOp[] memory ops) external;

    function manageUserBalance(UserBalanceOp[] memory ops) external payable;

    /**
     * @dev Simulates a call to `batchSwap`, returning an array of Vault asset
     * deltas. Calls to `swap` cannot be
     * simulated directly, but an equivalent `batchSwap` call can and will yield
     * the exact same result.
     *
     * Each element in the array corresponds to the asset at the same index, and
     * indicates the number of tokens (or ETH)
     * the Vault would take from the sender (if positive) or send to the
     * recipient (if negative). The arguments it
     * receives are the same that an equivalent `batchSwap` call would receive.
     *
     * Unlike `batchSwap`, this function performs no checks on the sender or
     * recipient field in the `funds` struct.
     * This makes it suitable to be called by off-chain applications via
     * eth_call without needing to hold tokens,
     * approve them for the Vault, or even know a user's address.
     *
     * Note that this function is not 'view' (due to implementation details):
     * the client code must explicitly execute
     * eth_call instead of eth_sendTransaction.
     */
    function queryBatchSwap(
        SwapKind kind,
        BatchSwapStep[] memory swaps,
        address[] memory assets,
        FundManagement memory funds
    ) external returns (int256[] memory);

    function registerPool(uint8 specialization) external returns (bytes32);

    function registerTokens(
        bytes32 poolId,
        address[] memory tokens,
        address[] memory assetManagers
    ) external;

    function setAuthorizer(address newAuthorizer) external;

    function setPaused(bool paused) external;

    function setRelayerApproval(address sender, address relayer, bool approved)
        external;

    /**
     * @dev Performs a swap with a single Pool.
     *
     * If the swap is 'given in' (the number of tokens to send to the Pool is
     * known), it returns the amount of tokens
     * taken from the Pool, which must be greater than or equal to `limit`.
     *
     * If the swap is 'given out' (the number of tokens to take from the Pool is
     * known), it returns the amount of tokens
     * sent to the Pool, which must be less than or equal to `limit`.
     *
     * Internal Balance usage and the recipient are determined by the `funds`
     * struct.
     *
     * Emits a `Swap` event.
     */
    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external payable returns (uint256);

    receive() external payable;

    function getPoolTokens(bytes32 poolId)
        external
        view
        returns (
            IERC20[] memory tokens,
            uint256[] memory balances,
            uint256 lastChangeBlock
        );

    enum SwapKind
    /// The number of tokens to send to the Pool is known
    {
        GIVEN_IN,
        /// The number of tokens to take from the Pool is known
        GIVEN_OUT
    }
}
