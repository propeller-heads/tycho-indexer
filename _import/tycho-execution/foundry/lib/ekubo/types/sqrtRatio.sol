// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

type SqrtRatio is uint96;

uint96 constant MIN_SQRT_RATIO_RAW = 4611797791050542631;
SqrtRatio constant MIN_SQRT_RATIO = SqrtRatio.wrap(MIN_SQRT_RATIO_RAW);
uint96 constant MAX_SQRT_RATIO_RAW = 79227682466138141934206691491;
SqrtRatio constant MAX_SQRT_RATIO = SqrtRatio.wrap(MAX_SQRT_RATIO_RAW);
