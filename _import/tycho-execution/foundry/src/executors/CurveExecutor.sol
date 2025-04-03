// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@interfaces/ICurveRouter.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

error CurveExecutor__InvalidAddresses();

contract CurveExecutor is IExecutor {
    using SafeERC20 for IERC20;

    ICurveRouter public immutable curveRouter;
    address public immutable nativeToken;

    /**
     * @dev Struct representing the parameters for a Curve swap.
     *
     * `route` is an array of [initial token, pool or zap, token, pool or zap, token, ...]
     * The array is iterated until a pool address of 0x00, then the last given token is transferred to `receiver`.
     *
     * `swapParams` is a multidimensional array of [i, j, swap_type, pool_type, n_coins] where:
     * - i is the index of input token
     * - j is the index of output token
     *
     * The swap_type should be:
     * 1. for `exchange`
     * 2. for `exchange_underlying`
     * 3. for underlying exchange via zap: factory stable metapools with lending base pool `exchange_underlying`
     *    and factory crypto-meta pools underlying exchange (`exchange` method in zap)
     * 4. for coin -> LP token "exchange" (actually `add_liquidity`)
     * 5. for lending pool underlying coin -> LP token "exchange" (actually `add_liquidity`)
     * 6. for LP token -> coin "exchange" (actually `remove_liquidity_one_coin`)
     * 7. for LP token -> lending or fake pool underlying coin "exchange" (actually `remove_liquidity_one_coin`)
     * 8. for ETH <-> WETH, ETH -> stETH or ETH -> frxETH, stETH <-> wstETH, frxETH <-> sfrxETH, ETH -> wBETH, USDe -> sUSDe
     *
     * pool_type: 1 - stable, 2 - twocrypto, 3 - tricrypto, 4 - llamma
     *            10 - stable-ng, 20 - twocrypto-ng, 30 - tricrypto-ng
     *
     * n_coins is the number of coins in the pool.
     *
     * `receiver` is the address of the receiver of the final token.
     *
     * `needsApproval` is a flag indicating whether the initial token needs approval before the swap.
     *
     * For more see https://github.com/curvefi/curve-router-ng/blob/9ab006ca848fc7f1995b6fbbecfecc1e0eb29e2a/contracts/Router.vy
     *
     */
    struct CurveSwapParams {
        address[11] route;
        uint256[5][5] swapParams;
        address receiver;
        bool needsApproval;
    }

    constructor(address _curveRouter, address _nativeToken) {
        if (_curveRouter == address(0) || _nativeToken == address(0)) {
            revert CurveExecutor__InvalidAddresses();
        }
        curveRouter = ICurveRouter(_curveRouter);
        nativeToken = _nativeToken;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256)
    {
        CurveSwapParams memory params = _decodeData(data);

        if (params.needsApproval) {
            // slither-disable-next-line unused-return
            IERC20(params.route[0]).approve(
                address(curveRouter), type(uint256).max
            );
        }
        // slither-disable-next-line uninitialized-local
        address[5] memory pools;
        return curveRouter.exchange{
            value: params.route[0] == nativeToken ? amountIn : 0
        }(params.route, params.swapParams, amountIn, 0, pools, params.receiver);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (CurveSwapParams memory params)
    {
        return abi.decode(data, (CurveSwapParams));
    }

    receive() external payable {
        require(msg.sender.code.length != 0);
    }
}
