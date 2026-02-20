// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IPartyPool} from "./IPartyPool.sol";

/// @title IPartyPlanner
/// @notice Interface for factory contract for creating and tracking PartyPool
/// instances
interface IPartyPlanner {
    /// @notice Retrieves a page of pool addresses
    /// @param offset Starting index for pagination
    /// @param limit Maximum number of items to return
    /// @return pools Array of pool addresses for the requested page
    function getAllPools(uint256 offset, uint256 limit)
        external
        view
        returns (IPartyPool[] memory pools);
}
