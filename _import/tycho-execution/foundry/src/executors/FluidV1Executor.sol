pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {TransferManager} from "../TransferManager.sol";

interface IFluidV1Dex {
    function swapInWithCallback(
        bool swap0to1_,
        uint256 amountIn_,
        uint256 amountOutMin_,
        address to_
    ) external payable returns (uint256 amountOut_);

    function swapIn(
        bool swap0to1_,
        uint256 amountIn_,
        uint256 amountOutMin_,
        address to_
    ) external payable returns (uint256 amountOut_);
}

error FluidV1Executor__ZeroLiquidityAddress();
error FluidV1Executor__ZeroDexFactoryAddress();
error FluidV1Executor__InvalidDataLength();
error FluidV1Executor__InvalidCallback();
error FluidV1Executor__InvalidDex(address dex);

contract FluidV1Executor is IExecutor, ICallback {
    // keccak(FluidV1Executor#CURRENT_DEX)
    // stores current dex address
    bytes32 private constant _CURRENT_DEX_SLOT =
        0x823205ddf0d345ca541c0f695a3f87b5dce7be9df5ecffce73a87e1ad796ad20;
    // dexCallback(address,amount)
    bytes4 private constant _CALLBACK_SELECTOR = 0x9410ae88;

    address public immutable liquidity;
    address public immutable dexFactory;

    constructor(address liquidity_, address dexFactory_) {
        if (liquidity_ == address(0)) {
            revert FluidV1Executor__ZeroLiquidityAddress();
        }
        if (dexFactory_ == address(0)) {
            revert FluidV1Executor__ZeroDexFactoryAddress();
        }
        liquidity = liquidity_;
        dexFactory = dexFactory_;
    }

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        IFluidV1Dex dex;
        bool zero2one;
        bool isNativeSell;
        uint32 dexId;

        (dex, zero2one, tokenOut, isNativeSell, dexId) = _decodeData(data);
        _verifyDex(address(dex), dexId);

        if (!isNativeSell) {
            _setCurrentDex(dex);
            amountOut = dex.swapInWithCallback(zero2one, amountIn, 0, receiver);
        } else {
            // This is safe since the router asserts that we received the required output token in return
            // slither-disable-next-line arbitrary-send-eth
            amountOut =
                dex.swapIn{value: amountIn}(zero2one, amountIn, 0, receiver);
        }
    }

    // Stores dex address in transient storage
    function _setCurrentDex(IFluidV1Dex dex) internal {
        // slither-disable-next-line assembly
        assembly {
            tstore(_CURRENT_DEX_SLOT, dex)
        }
    }

    function _getCurrentDex() internal view returns (address dex) {
        // slither-disable-next-line assembly
        assembly {
            dex := tload(_CURRENT_DEX_SLOT)
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IFluidV1Dex dex,
            bool zero2one,
            address tokenOut,
            bool isNativeSell,
            uint32 dexId
        )
    {
        // expected calldata layout
        // ---------------------
        // 0  | dex address
        // 20 | zero2one
        // 21 | tokenOut
        // 41 | is_native
        // 42 | dexId (uint32)
        // 46 | EOF
        if (data.length != 46) {
            revert FluidV1Executor__InvalidDataLength();
        }
        dex = IFluidV1Dex(address(bytes20(data[0:20])));
        zero2one = uint8(data[20]) > 0;
        tokenOut = address(bytes20(data[21:41]));
        isNativeSell = uint8(data[41]) > 0;
        dexId = uint32(bytes4(data[42:46]));
    }

    /// @dev Verifies a dex address by recomputing the address from (dexFactory, dexId).
    function _verifyDex(address dex, uint32 dexId) internal view {
        // The nonce is equal to the dexId
        // source: https://github.com/Instadapp/fluid-contracts-public/blob/a9949b48ba1247d4f478cd0acb40896b5c8bf3f8/contracts/protocols/dex/factory/main.sol#L246
        if (dex != _addressCalc(dexFactory, dexId)) {
            revert FluidV1Executor__InvalidDex(dex);
        }
    }

    /// @dev Computes the address for a given deployer and nonce.
    ///      Mirrors Fluid's AddressCalcs.addressCalc:
    ///      https://github.com/Instadapp/fluid-contracts-public/blob/a9949b48ba1247d4f478cd0acb40896b5c8bf3f8/contracts/libraries/addressCalcs.sol
    function _addressCalc(address deployer, uint256 nonce)
        internal
        pure
        returns (address)
    {
        bytes memory data;
        if (nonce == 0x00) {
            return address(0);
        } else if (nonce <= 0x7f) {
            data = abi.encodePacked(
                bytes1(0xd6), bytes1(0x94), deployer, uint8(nonce)
            );
        } else if (nonce <= 0xff) {
            data = abi.encodePacked(
                bytes1(0xd7), bytes1(0x94), deployer, bytes1(0x81), uint8(nonce)
            );
        } else if (nonce <= 0xffff) {
            data = abi.encodePacked(
                bytes1(0xd8),
                bytes1(0x94),
                deployer,
                bytes1(0x82),
                uint16(nonce)
            );
        } else if (nonce <= 0xffffff) {
            data = abi.encodePacked(
                bytes1(0xd9),
                bytes1(0x94),
                deployer,
                bytes1(0x83),
                uint24(nonce)
            );
        } else {
            data = abi.encodePacked(
                bytes1(0xda),
                bytes1(0x94),
                deployer,
                bytes1(0x84),
                uint32(nonce)
            );
        }
        return address(uint160(uint256(keccak256(data))));
    }

    function handleCallback(bytes calldata data)
        public
        view
        returns (bytes memory result)
    {
        verifyCallback(data);
        result = "";
    }

    function verifyCallback(bytes calldata data) public view {
        address dex = _getCurrentDex();
        bytes4 selector = bytes4(data[:4]);
        if (msg.sender != dex || selector != _CALLBACK_SELECTOR) {
            revert FluidV1Executor__InvalidCallback();
        }
    }

    function getTransferData(
        bytes calldata /* data */
    )
        external
        payable
        returns (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        return (TransferManager.TransferType.None, address(0), address(0));
    }

    function getCallbackTransferData(bytes calldata data)
        external
        payable
        returns (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            uint256 amount
        )
    {
        (tokenIn, amount) = abi.decode(data[4:68], (address, uint256));
        if (tokenIn == address(0)) {
            // ETH transfers are handled in the Executor, so we need to set the transferType to TransferNativeInExecutor
            // to update the delta accounting accordingly.
            transferType = TransferManager.TransferType.TransferNativeInExecutor;
        } else {
            transferType = TransferManager.TransferType.Transfer;
        }
        receiver = liquidity;
    }
}
