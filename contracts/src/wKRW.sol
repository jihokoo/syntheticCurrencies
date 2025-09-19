// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title WKRW — ERC20 with role-based minting for KRW units
 * @notice 1 wKRW = 1 KRW (with 18 decimals for DeFi compatibility).
 *         Admin (DEFAULT_ADMIN_ROLE) can grant/revoke MINTER_ROLE to modules (e.g., SwapModule).
 */

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract wKRW is ERC20, ERC20Burnable, ERC20Permit, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(
        address admin
    ) ERC20("Wrapped KRW", "wKRW") ERC20Permit("wKRW") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Mint wKRW to `to`. Caller must have MINTER_ROLE.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @notice Optional minter burn (useful in redeem flows with allowance already handled in module).
    function burnFromAsMinter(
        address from,
        uint256 amount
    ) external onlyRole(MINTER_ROLE) {
        _burn(from, amount);
    }
}
