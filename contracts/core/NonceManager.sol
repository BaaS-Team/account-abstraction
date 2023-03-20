// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../interfaces/IEntryPoint.sol";
import "hardhat/console.sol";

/**
 * nonce management functionality
 */
contract NonceManager is INonceManager {

    mapping(address => mapping(uint192 => uint256)) public nonces;

    uint192 constant KEY_OFFSET = 0;

    function getNonce(address sender, uint192 key)
    public view override returns (uint256 nonce) {
        return nonces[sender][key + KEY_OFFSET] | (uint256(key) << 64);
    }

    // allow an account to manually increment its own nonce.
    // (mainly so that during construction nonce can be made non-zero, 
    // to "absorb" the gas cost of first nonce increment to 1st transaction (construction),
    // not to 2nd transaction)
    function incrementNonce(uint192 key) public override {
        nonces[msg.sender][key + KEY_OFFSET]++;
    }

    /**
     * validate nonce uniqueness for this account.
     * called just after validateUserOp()
     */
    function _validateAndUpdateNonce(address sender, uint256 nonce) internal returns (bool) {

        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        return nonces[sender][key + KEY_OFFSET]++ == seq;
    }

}
