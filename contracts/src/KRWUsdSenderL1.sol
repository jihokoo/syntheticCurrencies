// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Client} from "@chainlink/contracts-ccip/contracts/libraries/Client.sol";
import {IRouterClient} from "@chainlink/contracts-ccip/contracts/interfaces/IRouterClient.sol";

/**
 * @title KRWUsdSenderL1
 * @notice Reads Chainlink KRW/USD (Ethereum) OR uses a fixed price (for testnets),
 *         then sends (px1e18, updatedAt) to Base via Chainlink CCIP.
 *
 * Usage:
 * - Mainnet:   useFixed=false, set _krwUsd to Chainlink feed.
 * - Sepolia:   useFixed=true,  fixedPx1e18=1300e18 (1 USD = 1300 KRW), _krwUsd can be zero addr.
 */

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256 updatedAt, uint80);
    function decimals() external view returns (uint8);
}

contract KRWUsdSenderL1 {
    // --- Immutable CCIP wiring ---
    IRouterClient public immutable ccipRouter; // CCIP Router on Ethereum
    address public receiverOnBase; // Base adapter address
    uint64 public baseSelector; // Chain selector for Base

    // --- Price source configuration ---
    bool public useFixed; // true => use fixedPx1e18; false => use Chainlink feed
    uint256 public fixedPx1e18; // KRW per 1 USD, scaled 1e18 (e.g., 1300e18)
    AggregatorV3Interface public krwUsdL1; // KRW per 1 USD Chainlink feed (optional when useFixed=true)

    // --- Admin ---
    address public owner;

    // --- Events ---
    event Sent(bytes32 msgId, uint256 px1e18, uint256 updatedAt);
    event ReceiverSet(address receiver);
    event BaseSelectorSet(uint64 selector);
    event FixedModeSet(bool useFixed, uint256 fixedPx1e18);
    event FeedSet(address feed);
    event OwnerSet(address owner);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /**
     * @param _router        CCIP Router (Ethereum)
     * @param _receiverOnBase Base adapter address (on Base)
     * @param _baseSelector  Chain selector for Base
     * @param _useFixed      true to use fixed price mode (testnets), false to use Chainlink feed
     * @param _fixedPx1e18   Fixed KRW/USD price scaled 1e18 (ignored if _useFixed=false)
     * @param _krwUsd        Chainlink KRW/USD feed (can be zero if _useFixed=true)
     * @param _owner         Admin address for updates
     */
    constructor(
        address _router,
        address _receiverOnBase,
        uint64 _baseSelector,
        bool _useFixed,
        uint256 _fixedPx1e18,
        address _krwUsd,
        address _owner
    ) {
        require(
            _router != address(0) &&
                _receiverOnBase != address(0) &&
                _owner != address(0),
            "zero"
        );
        ccipRouter = IRouterClient(_router);
        receiverOnBase = _receiverOnBase;
        baseSelector = _baseSelector;

        useFixed = _useFixed;
        fixedPx1e18 = _fixedPx1e18;
        krwUsdL1 = AggregatorV3Interface(_krwUsd);
        owner = _owner;

        if (!_useFixed) {
            require(_krwUsd != address(0), "feed required");
        }
    }

    // KRWUsdSenderL1.sol (add)
    function getRouter() external view returns (address) {
        return address(ccipRouter);
    }

    // -------- Admin setters --------
    function setReceiverOnBase(address r) external onlyOwner {
        require(r != address(0), "zero");
        receiverOnBase = r;
        emit ReceiverSet(r);
    }

    function setBaseSelector(uint64 s) external onlyOwner {
        baseSelector = s;
        emit BaseSelectorSet(s);
    }

    /// @notice Enable/disable fixed mode and/or update the fixed price (1e18 scaled).
    function setFixedMode(
        bool _useFixed,
        uint256 _fixedPx1e18
    ) external onlyOwner {
        useFixed = _useFixed;
        fixedPx1e18 = _fixedPx1e18;
        emit FixedModeSet(_useFixed, _fixedPx1e18);
    }

    /// @notice Set/replace the Chainlink feed (only used if useFixed=false).
    function setFeed(address _krwUsd) external onlyOwner {
        require(_krwUsd != address(0), "zero");
        krwUsdL1 = AggregatorV3Interface(_krwUsd);
        emit FeedSet(_krwUsd);
    }

    function setOwner(address _owner) external onlyOwner {
        require(_owner != address(0), "zero");
        owner = _owner;
        emit OwnerSet(_owner);
    }

    // -------- Main action: push price to Base via CCIP --------
    /// @notice Sends (px1e18, updatedAt) to Base. Attach ETH to cover CCIP fee.
    function pushOnce() external payable {
        (uint256 px, uint256 ts) = _readKrwUsd();

        Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
            receiver: abi.encode(receiverOnBase), // must be abi.encode
            data: abi.encode(px, ts), // payload
            tokenAmounts: new Client.EVMTokenAmount[](0), // no tokens
            extraArgs: Client._argsToBytes( // add gas limit
                    Client.EVMExtraArgsV1({gasLimit: 200000})
                ),
            feeToken: address(0) // pay in native ETH
        });

        uint256 fee = IRouterClient(ccipRouter).getFee(baseSelector, message);
        require(msg.value >= fee, "Insufficient fee");

        bytes32 msgId = IRouterClient(ccipRouter).ccipSend{value: fee}(
            baseSelector,
            message
        );
        emit Sent(msgId, px, ts);

        if (msg.value > fee) {
            uint256 refund = msg.value - fee;
            (bool ok, ) = msg.sender.call{value: refund}("");
            require(ok, "refund fail");
        }
    }

    function quoteFee() external view returns (uint256) {
        Client.EVM2AnyMessage memory m = Client.EVM2AnyMessage({
            receiver: abi.encode(receiverOnBase),
            data: abi.encode(uint256(1300e18), block.timestamp), // or your actual payload
            tokenAmounts: new Client.EVMTokenAmount[](0),
            extraArgs: Client._argsToBytes(
                Client.EVMExtraArgsV1({gasLimit: 200000})
            ),
            feeToken: address(0) // pay in native
        });
        return IRouterClient(ccipRouter).getFee(baseSelector, m);
    }

    // -------- Internals --------
    function _readKrwUsd()
        internal
        view
        returns (uint256 px1e18, uint256 updatedAt)
    {
        if (useFixed) {
            require(fixedPx1e18 > 0, "fixed=0");
            // Use current block time as publish timestamp for test mode
            return (fixedPx1e18, block.timestamp);
        } else {
            (, int256 answer, , uint256 ts, ) = krwUsdL1.latestRoundData();
            require(answer > 0, "bad feed");
            uint8 dec = krwUsdL1.decimals();
            require(dec <= 18, "bad decimals");
            // normalize to 1e18
            px1e18 = uint256(answer) * (10 ** (18 - dec));
            updatedAt = ts;
        }
    }

    receive() external payable {}
}
