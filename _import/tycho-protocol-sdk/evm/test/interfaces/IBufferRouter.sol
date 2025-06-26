// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.26;

import {IERC4626} from
    "openzeppelin-contracts/contracts/interfaces/IERC4626.sol";

interface IBufferRouter {
    function initializeBuffer(
        IERC4626 wrappedToken,
        uint256 exactAmountUnderlyingIn,
        uint256 exactAmountWrappedIn,
        uint256 minIssuedShares
    ) external returns (uint256 issuedShares);
}
