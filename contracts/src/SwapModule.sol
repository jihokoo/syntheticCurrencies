// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SwapModule (Base)
 * @notice ETH <-> wKRW swaps at oracle FX rate.
 *         - depositETHForKRW(): price ETH->USD (Base feed) then USD->KRW (adapter) and mint wKRW
 *         - redeemKRWForETH(): burn wKRW and return ETH at oracle rate
 *         - Fees in bps, daily mint cap, pausability, reentrancy guard
 *
 * SECURITY:
 * - Keep tight staleness windows.
 * - Consider adding Base L2 Sequencer Uptime grace check if you rely on Base feeds elsewhere.
 */

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {Ownable, Ownable2Step} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IOracleAdapter} from "./IOracleAdapter.sol";

interface IWKRW is IERC20 {
    function mint(address to, uint256 amt) external;
    function burnFromAsMinter(address from, uint256 amt) external;
}

contract SwapModule is ReentrancyGuard, Pausable, Ownable2Step {
    IWKRW public immutable wkrw;
    IOracleAdapter public adapter;

    uint256 public maxPriceAge = 30 minutes; // secondary guard (adapter should also guard)
    uint256 public mintFeeBps = 20; // 0.20%
    uint256 public redeemFeeBps = 20; // 0.20%
    address public feeRecipient;

    // daily mint limiter in KRW units (18 decimals)
    uint256 public dailyMintCap = 10_000_000e18;
    uint256 public dayStart;
    uint256 public mintedToday;

    event Deposited(
        address indexed user,
        uint256 ethIn,
        uint256 krwOut,
        uint256 feeKrw
    );
    event Redeemed(
        address indexed user,
        uint256 krwIn,
        uint256 ethOut,
        uint256 feeEth
    );
    event FeesUpdated(
        uint256 mintFeeBps,
        uint256 redeemFeeBps,
        address feeRecipient
    );
    event CapsUpdated(uint256 dailyMintCap);
    event AdapterUpdated(address adapter);
    event LimitsUpdated(uint256 maxPriceAge);

    constructor(
        address _wkrw,
        address _adapter,
        address _feeRecipient
    ) Ownable(msg.sender) {
        require(_wkrw != address(0) && _adapter != address(0), "zero addr");
        wkrw = IWKRW(_wkrw);
        adapter = IOracleAdapter(_adapter);
        feeRecipient = _feeRecipient;
        dayStart = _dayBucket(block.timestamp);
    }

    // -------- User flows --------

    /// @notice Swap ETH -> wKRW at oracle rate, minus fee
    function depositETHForKRW(
        address to
    ) external payable nonReentrant whenNotPaused returns (uint256 krwOut) {
        require(msg.value > 0, "no ETH");

        (uint256 usdPerEth, uint256 ts1) = adapter.getEthUsd(); // USD per 1 ETH
        (uint256 krwPerUsd, uint256 ts2) = adapter.getKrwUsd(); // KRW per 1 USD
        _fresh(ts1);
        _fresh(ts2);

        uint256 usdValue = (msg.value * usdPerEth) / 1e18;
        uint256 krwValue = (usdValue * krwPerUsd) / 1e18;

        uint256 fee = (krwValue * mintFeeBps) / 10_000;
        krwOut = krwValue - fee;

        _rollDay();
        require(mintedToday + krwOut <= dailyMintCap, "daily cap");

        wkrw.mint(to, krwOut);
        if (fee > 0 && feeRecipient != address(0)) {
            wkrw.mint(feeRecipient, fee);
        }

        mintedToday += krwOut;
        emit Deposited(msg.sender, msg.value, krwOut, fee);
    }

    /// @notice Swap wKRW -> ETH at oracle rate, minus fee
    function redeemKRWForETH(
        uint256 krwIn,
        address payable to
    ) external nonReentrant whenNotPaused returns (uint256 ethOut) {
        require(krwIn > 0, "no KRW");

        (uint256 usdPerEth, uint256 ts1) = adapter.getEthUsd(); // USD per 1 ETH
        (uint256 krwPerUsd, uint256 ts2) = adapter.getKrwUsd(); // KRW per 1 USD
        _fresh(ts1);
        _fresh(ts2);

        uint256 usdValue = (krwIn * 1e18) / krwPerUsd;
        uint256 ethValue = (usdValue * 1e18) / usdPerEth;

        uint256 fee = (ethValue * redeemFeeBps) / 10_000;
        ethOut = ethValue - fee;
        require(address(this).balance >= ethOut, "insufficient ETH");

        wkrw.burnFromAsMinter(msg.sender, krwIn);

        (bool ok, ) = to.call{value: ethOut}("");
        require(ok, "eth xfer");

        if (fee > 0 && feeRecipient != address(0)) {
            (ok, ) = payable(feeRecipient).call{value: fee}("");
            require(ok, "fee xfer");
        }

        emit Redeemed(msg.sender, krwIn, ethOut, fee);
    }

    // -------- Admin --------
    function setAdapter(address a) external onlyOwner {
        require(a != address(0), "zero");
        adapter = IOracleAdapter(a);
        emit AdapterUpdated(a);
    }

    function setFees(
        uint256 _mintFeeBps,
        uint256 _redeemFeeBps,
        address _feeRecipient
    ) external onlyOwner {
        require(_mintFeeBps <= 200 && _redeemFeeBps <= 200, "fees too high");
        mintFeeBps = _mintFeeBps;
        redeemFeeBps = _redeemFeeBps;
        feeRecipient = _feeRecipient;
        emit FeesUpdated(_mintFeeBps, _redeemFeeBps, _feeRecipient);
    }

    function setDailyMintCap(uint256 c) external onlyOwner {
        dailyMintCap = c;
        emit CapsUpdated(c);
    }

    function setLimits(uint256 _maxPriceAge) external onlyOwner {
        require(_maxPriceAge >= 30 seconds, "bad");
        maxPriceAge = _maxPriceAge;
        emit LimitsUpdated(_maxPriceAge);
    }

    function pause() external onlyOwner {
        _pause();
    }
    function unpause() external onlyOwner {
        _unpause();
    }

    // -------- Internals --------
    function _fresh(uint256 ts) internal view {
        require(block.timestamp - ts <= maxPriceAge, "stale");
    }
    function _dayBucket(uint256 t) internal pure returns (uint256) {
        return (t / 1 days) * 1 days;
    }
    function _rollDay() internal {
        uint256 b = _dayBucket(block.timestamp);
        if (b > dayStart) {
            dayStart = b;
            mintedToday = 0;
        }
    }

    receive() external payable {}
}
