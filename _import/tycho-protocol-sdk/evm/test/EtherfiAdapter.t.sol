// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/etherfi/EtherfiAdapter.sol";

contract EtherfiAdapterTest is Test, ISwapAdapterTypes {
    EtherfiAdapter adapter;
    IWeEth wEeth = IWeEth(0xCd5fE23C85820F7B72D0926FC9b05b43E359b7ee);
    IeEth eEth;

    function setUp() public {
        uint256 forkBlock = 19218495;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        adapter = new EtherfiAdapter(address(wEeth));
        eEth = wEeth.eETH();

        vm.label(address(wEeth), "WeETH");
        vm.label(address(eEth), "eETH");
    }

    receive() external payable {}

    function testMe() public {
        // // uint256 requiredETH = adapter.getETHRequiredToMintEeth(1 ether);
        // deal(address(adapter), 100 ether);
        // // adapter.swapEthForEeth(1 ether, OrderSide.Buy);
        // IERC20(address(eEth)).approve(address(adapter), type(uint256).max);

        // console.log(IERC20(address(eEth)).balanceOf(address(this)));
        // console.log(adapter.swapEthForWeEth(1 ether, OrderSide.Buy));
        // console.log(IERC20(address(eEth)).balanceOf(address(this)));
    }
}
