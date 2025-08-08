// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IFlashAccountant} from "./IFlashAccountant.sol";
import {PoolKey} from "../types/poolKey.sol";
import {SqrtRatio} from "../types/sqrtRatio.sol";

interface ICore is IFlashAccountant {
    function swap_611415377(
        PoolKey memory poolKey,
        int128 amount,
        bool isToken1,
        SqrtRatio sqrtRatioLimit,
        uint256 skipAhead
    ) external payable returns (int128 delta0, int128 delta1);
}
