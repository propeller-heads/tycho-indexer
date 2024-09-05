// SPDX-License-Identifier: MIT
pragma solidity >=0.4.0;

interface ICurveCryptoPool {
    function get_dy(uint256 i, uint256 j, uint256 dx)
        external
        view
        returns (uint256);

    // tricrypto
    function exchange(
        uint256 i,
        uint256 j,
        uint256 dx,
        uint256 min_dy,
        bool use_eth
    ) external payable;

    // eth accepting pools
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy)
        external
        payable
        returns (uint256);

    function coins(uint256 i) external view returns (address);
}
