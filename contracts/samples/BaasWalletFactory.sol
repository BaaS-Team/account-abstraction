// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./BaasWallet.sol";
import "../interfaces/IAggregator.sol";

/**
 * @title  BaasWalletFactory
 * @notice A factory contract for BaasWallet
 */
contract BaasWalletFactory {
    BaasWallet public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint, IAggregator _aggregator, address dkim){
        accountImplementation = new BaasWallet(_entryPoint, _aggregator, dkim);
    }

    /**
     * @notice create an account, and return its address.
     * @param owner The addree of account owner.
     * @param server The address of the multi-signature server.
     * @param salt The salt to create the account address.
     * @param blsPublicKey The public key of the aggregate signature.
     */
    function createAccount(address owner, address server, uint salt, uint256[4] memory blsPublicKey) public returns (BaasWallet ret) {
        address addr = getAddress(owner, server, salt, blsPublicKey);
        uint codeSize = addr.code.length;
        
        if (codeSize > 0) {
            return BaasWallet(payable(addr));
        }

        ret = BaasWallet(payable(new ERC1967Proxy{salt : bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(BaasWallet.initialize, (owner, server, blsPublicKey))
            )));
    }

    /**
     * @notice calculate the counterfactual address of this account as it would be returned by createAccount()
     * @param owner The addree of account owner.
     * @param server The address of the multi-signature server.
     * @param salt The salt to create the account address.
     * @param blsPublicKey The public key of the aggregate signature.
     */
    function getAddress(address owner, address server, uint salt, uint256[4] memory blsPublicKey) public view returns (address) {
        return Create2.computeAddress(bytes32(salt), keccak256(abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(accountImplementation),
                    abi.encodeCall(BaasWallet.initialize, (owner, server, blsPublicKey))
                )
            )));
    }
}
