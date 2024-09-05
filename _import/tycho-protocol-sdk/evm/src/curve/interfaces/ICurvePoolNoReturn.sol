// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

interface ICurvePoolNoReturn {
    function get_dy(int128 i, int128 j, uint256 dx)
        external
        view
        returns (uint256);

    function get_dy_underlying(int128 i, int128 j, uint256 dx)
        external
        view
        returns (uint256);

    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy)
        external;

    function exchange_underlying(int128 i, int128 j, uint256 dx, uint256 min_dy)
        external;
    function coins(int128 arg0) external view returns (address);
    function underlying_coins(int128 arg0) external view returns (address);
}
