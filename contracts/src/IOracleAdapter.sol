// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Normalized oracle interface used by SwapModule.
interface IOracleAdapter {
    /// @dev Returns USD per 1 ETH, scaled to 1e18, and the feed's updatedAt timestamp.
    function getEthUsd() external view returns (uint256 px, uint256 updatedAt);

    /// @dev Returns KRW per 1 USD, scaled to 1e18, and the feed's updatedAt timestamp.
    function getKrwUsd() external view returns (uint256 px, uint256 updatedAt);
}
