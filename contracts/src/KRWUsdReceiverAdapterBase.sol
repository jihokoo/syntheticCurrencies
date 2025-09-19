// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title KRWUsdReceiverAdapterBase
 * @notice Base-side CCIP receiver that stores KRW/USD (1e18) and exposes:
 *         - getKrwUsd() for SwapModule
 *         - getEthUsd() by reading Chainlink's Base ETH/USD feed
 * @dev Uses Chainlink for ETH/USD and a fixed 1300 KRW per USD test value.
 */

import {IOracleAdapter} from "./IOracleAdapter.sol";

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256 updatedAt, uint80);
    function decimals() external view returns (uint8);
}

contract KRWUsdReceiverAdapterBase is IOracleAdapter {
    // --- Admin ---
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    // --- ETH/USD on Base (Chainlink) ---
    AggregatorV3Interface public ethUsdBase;
    uint256 public maxEthAge = 30 minutes;

    // --- Fixed KRW/USD (testnet) ---
    uint256 public fixedKrwUsd = 1300e18;

    event LimitsSet(uint256 maxEthAge, uint256 maxKrwAge);
    event EthFeedSet(address feed);
    event FixedKrwUsdSet(uint256 px1e18);

    constructor(
        address _owner,
        address _ethUsdBase
    ) {
        require(
            _owner != address(0) && _ethUsdBase != address(0),
            "zero"
        );
        owner = _owner;
        ethUsdBase = AggregatorV3Interface(_ethUsdBase);
    }

    // ---- Admin ----
    function setLimits(uint256 eAge, uint256 /*kAge*/ ) external onlyOwner {
        require(eAge >= 30 seconds, "bad");
        maxEthAge = eAge;
        emit LimitsSet(eAge, 0);
    }
    function setEthUsdFeed(address f) external onlyOwner {
        require(f != address(0), "zero");
        ethUsdBase = AggregatorV3Interface(f);
        emit EthFeedSet(f);
    }
    function setFixedKrwUsd(uint256 px1e18) external onlyOwner {
        require(px1e18 > 0, "bad fixed");
        fixedKrwUsd = px1e18;
        emit FixedKrwUsdSet(px1e18);
    }

    // ---- IOracleAdapter ----
    function getEthUsd() external view returns (uint256 px, uint256 updatedAt) {
        (, int256 answer, , uint256 ts, ) = ethUsdBase.latestRoundData();
        require(answer > 0, "bad ETH/USD");
        require(block.timestamp - ts <= maxEthAge, "stale ETH/USD");
        uint8 dec = ethUsdBase.decimals();
        require(dec <= 18, "bad decimals");
        px = uint256(answer) * (10 ** (18 - dec));
        updatedAt = ts;
    }

    function getKrwUsd() external view returns (uint256 px1e18, uint256 ts) {
        px1e18 = fixedKrwUsd;
        ts = block.timestamp;
    }
}
