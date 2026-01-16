// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

error FeeTaker__InvalidDataLength();
error FeeTaker__FeeTooHigh();
error FeeTaker__AddressZero();

/**
 * @title FeeTaker
 * @notice Contract responsible for calculating fees on swap outputs and managing fee configuration
 * @dev This contract is called via staticCall from TychoRouter.
 *      It calculates fees and returns the values - accounting is done by the caller.
 *      It also stores all fee-related configuration.
 */
contract FeeTaker is AccessControl {
    uint16 private constant MAX_FEE_BPS = 10000; // 100% max

    uint16 private _routerFeeOnOutputBps; // Router fee on output amount in basis points
    uint16 private _routerFeeOnSolverFeeBps; // Router fee on solver fee in basis points
    address private _routerFeeReceiver; // Address whose vault balance receives router fees

    // Per-user custom router fees on output amount
    // If set, this will override the default router fee on output for the user
    mapping(address => bool) private _hasCustomRouterFeeOnOutput;
    mapping(address => uint16) private _customRouterFeeOnOutput;

    // Per-user custom router fees on solver fee
    // If set, this will override the default router fee on the solver fee for the user
    mapping(address => bool) private _hasCustomRouterFeeOnSolverFee;
    mapping(address => uint16) private _customRouterFeeOnSolverFee;

    //keccak256("ROUTER_FEE_SETTER_ROLE")
    bytes32 public constant ROUTER_FEE_SETTER_ROLE =
        0x9939157be7760e9462f1d5a0dcad88b616ddc64138e317108b40b1cf55601348;

    event RouterFeeOnOutputUpdated(uint16 oldFeeBps, uint16 newFeeBps);
    event RouterFeeOnSolverFeeUpdated(uint16 oldFeeBps, uint16 newFeeBps);
    event CustomRouterFeeOnOutputUpdated(
        address indexed user, uint16 oldFeeBps, uint16 newFeeBps
    );
    event CustomRouterFeeOnSolverFeeUpdated(
        address indexed user, uint16 oldFeeBps, uint16 newFeeBps
    );
    event CustomRouterFeeOnOutputRemoved(address indexed user);
    event CustomRouterFeeOnSolverFeeRemoved(address indexed user);
    event RouterFeeReceiverUpdated(
        address indexed oldReceiver, address indexed newReceiver
    );

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _routerFeeReceiver = msg.sender;
    }

    /**
     * @notice Calculates fees from the swap output amount
     * @dev Called via delegatecall from TychoRouter. Does not perform any accounting.
     * @param amountIn The amount before fee deduction
     * @param data Encoded fee parameters (46 bytes total):
     *        - solverFeeBps (uint16): Solver fee in basis points
     *        - solverFeeReceiver (address): Address to receive solver fee
     *        - routerFeeOnOutputBps (uint16): Router fee on output in basis points
     *        - routerFeeOnSolverFeeBps (uint16): Router fee on solver fee in basis points
     *        - routerFeeReceiver (address): Address to receive router fees
     * @return amountOut The amount remaining after all fee deductions
     * @return routerFee Total router fee amount
     * @return routerFeeReceiverAddr Address to receive router fees
     * @return solverFee Solver fee amount (after router's cut)
     * @return solverFeeReceiverAddr Address to receive solver fee
     */
    function takeFee(uint256 amountIn, bytes calldata data)
        external
        pure
        returns (
            uint256 amountOut,
            uint256 routerFee,
            address routerFeeReceiverAddr,
            uint256 solverFee,
            address solverFeeReceiverAddr
        )
    {
        (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver
        ) = _decodeFeeData(data);

        if (
            (solverFeeBps + routerFeeOnOutputBps > MAX_FEE_BPS)
                || routerFeeOnSolverFeeBps > MAX_FEE_BPS
        ) {
            revert FeeTaker__FeeTooHigh();
        }

        amountOut = amountIn;
        uint256 routerFeeOnSolverFee = 0;
        uint256 solverPortion = 0;

        // Calculate solver fee if > 0
        if (solverFeeBps > 0) {
            // Save numerator for later routerFeeOnSolverFee calculation to avoid
            // divide-before-multiply precision loss and warning
            uint256 solverFeeNumerator = amountOut * solverFeeBps;
            uint256 totalSolverFee = solverFeeNumerator / 10_000;
            amountOut -= totalSolverFee;

            // Calculate router's cut of the solver fee
            if (routerFeeOnSolverFeeBps > 0) {
                routerFeeOnSolverFee =
                    (solverFeeNumerator * routerFeeOnSolverFeeBps) / 100_000_000;
            }

            // Solver gets their portion (after router's cut)
            solverPortion = totalSolverFee - routerFeeOnSolverFee;
        }

        uint256 totalRouterFee = routerFeeOnSolverFee;

        // Calculate router fee on output amount if > 0
        if (routerFeeOnOutputBps > 0) {
            uint256 routerFeeOnOutput =
                (amountOut * routerFeeOnOutputBps) / 10000;
            amountOut -= routerFeeOnOutput;
            totalRouterFee += routerFeeOnOutput;
        }

        return (
            amountOut,
            totalRouterFee,
            routerFeeReceiver,
            solverPortion,
            solverFeeReceiver
        );
    }

    /**
     * @notice Decodes the fee data parameters
     * @param data Encoded fee parameters
     * @return solverFeeBps Solver fee in basis points
     * @return solverFeeReceiver Address to receive solver fee
     * @return routerFeeOnOutputBps Router fee on output in basis points
     * @return routerFeeOnSolverFeeBps Router fee on solver fee in basis points
     * @return routerFeeReceiver Address to receive router fees
     */
    function _decodeFeeData(bytes calldata data)
        internal
        pure
        returns (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver
        )
    {
        if (data.length != 46) {
            revert FeeTaker__InvalidDataLength();
        }

        solverFeeBps = uint16(bytes2(data[0:2]));
        solverFeeReceiver = address(bytes20(data[2:22]));
        routerFeeOnOutputBps = uint16(bytes2(data[22:24]));
        routerFeeOnSolverFeeBps = uint16(bytes2(data[24:26]));
        routerFeeReceiver = address(bytes20(data[26:46]));
    }

    /**
     * @dev Sets the router fee on output amount in basis points
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setRouterFeeOnOutput(uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _routerFeeOnOutputBps;
        _routerFeeOnOutputBps = feeBps;
        emit RouterFeeOnOutputUpdated(oldFeeBps, feeBps);
    }

    /**
     * @dev Returns the current router fee on output amount in basis points
     * @return The fee in basis points
     */
    function getRouterFeeOnOutput() external view returns (uint16) {
        return _routerFeeOnOutputBps;
    }

    /**
     * @dev Sets a custom router fee on output amount for a specific user
     * @param user The user address to set the custom fee for
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setCustomRouterFeeOnOutput(address user, uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _hasCustomRouterFeeOnOutput[user]
            ? _customRouterFeeOnOutput[user]
            : _routerFeeOnOutputBps;
        _customRouterFeeOnOutput[user] = feeBps;
        _hasCustomRouterFeeOnOutput[user] = true;
        emit CustomRouterFeeOnOutputUpdated(user, oldFeeBps, feeBps);
    }

    /**
     * @dev Removes the custom router fee on output amount for a specific user, reverting to default
     * @param user The user address to remove the custom fee from
     */
    function removeCustomRouterFeeOnOutput(address user)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        _hasCustomRouterFeeOnOutput[user] = false;
        delete _customRouterFeeOnOutput[user];
        emit CustomRouterFeeOnOutputRemoved(user);
    }

    /**
     * @dev Returns the effective router fee on output amount for a specific user
     * @param user The user address to check
     * @return The fee in basis points (custom if set, otherwise default)
     */
    function getCustomRouterFeeOnOutput(address user)
        external
        view
        returns (uint16)
    {
        return _hasCustomRouterFeeOnOutput[user]
            ? _customRouterFeeOnOutput[user]
            : _routerFeeOnOutputBps;
    }

    /**
     * @dev Sets the router platform fee on solver fee in basis points
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setRouterFeeOnSolverFee(uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _routerFeeOnSolverFeeBps;
        _routerFeeOnSolverFeeBps = feeBps;
        emit RouterFeeOnSolverFeeUpdated(oldFeeBps, feeBps);
    }

    /**
     * @dev Returns the current router platform fee on solver fee in basis points
     * @return The fee in basis points
     */
    function getRouterFeeOnSolverFee() external view returns (uint16) {
        return _routerFeeOnSolverFeeBps;
    }

    /**
     * @dev Sets a custom router fee on solver fee for a specific user
     * @param user The user address to set the custom fee for
     * @param feeBps The fee in basis points (e.g., 1 = 0.01%, 100 = 1%)
     */
    function setCustomRouterFeeOnSolverFee(address user, uint16 feeBps)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        uint16 oldFeeBps = _hasCustomRouterFeeOnSolverFee[user]
            ? _customRouterFeeOnSolverFee[user]
            : _routerFeeOnSolverFeeBps;
        _customRouterFeeOnSolverFee[user] = feeBps;
        _hasCustomRouterFeeOnSolverFee[user] = true;
        emit CustomRouterFeeOnSolverFeeUpdated(user, oldFeeBps, feeBps);
    }

    /**
     * @dev Removes the custom router fee on solver fee for a specific user, reverting to default
     * @param user The user address to remove the custom fee from
     */
    function removeCustomRouterFeeOnSolverFee(address user)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        _hasCustomRouterFeeOnSolverFee[user] = false;
        delete _customRouterFeeOnSolverFee[user];
        emit CustomRouterFeeOnSolverFeeRemoved(user);
    }

    /**
     * @dev Returns the effective router fee on solver fee for a specific user
     * @param user The user address to check
     * @return The fee in basis points (custom if set, otherwise default)
     */
    function getCustomRouterFeeOnSolverFee(address user)
        external
        view
        returns (uint16)
    {
        return _hasCustomRouterFeeOnSolverFee[user]
            ? _customRouterFeeOnSolverFee[user]
            : _routerFeeOnSolverFeeBps;
    }

    /**
     * @dev Sets the address that receives router fees
     * @param routerFeeReceiver The address to receive router fees
     */
    function setRouterFeeReceiver(address routerFeeReceiver)
        external
        onlyRole(ROUTER_FEE_SETTER_ROLE)
    {
        if (routerFeeReceiver == address(0)) {
            revert FeeTaker__AddressZero();
        }
        address oldReceiver = _routerFeeReceiver;
        _routerFeeReceiver = routerFeeReceiver;
        emit RouterFeeReceiverUpdated(oldReceiver, routerFeeReceiver);
    }

    /**
     * @dev Returns the current router fee receiver address
     */
    function getRouterFeeReceiver() external view returns (address) {
        return _routerFeeReceiver;
    }
}
