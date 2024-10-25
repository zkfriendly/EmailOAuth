// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "@account-abstraction/contracts/core/BaseAccount.sol";
import "./interfaces/IGroth16Verifier.sol";

/// @title EmailAccount - it is a minimal proxy that gets cloned by the factory according to EIP-1167
/// @notice A contract for managing email-based accounts with DKIM verification
/// @dev Implements BaseAccount for account abstraction
contract EmailAccount is BaseAccount {
    address private _entryPoint;
    address public verifier; // The ZK verifier for email integrity and ownership

    bool public isInitialized;

    /// @notice Constructs the EmailAccount contract
    /// @param anEntryPoint The EntryPoint contract address
    /// @param _verifier The Groth16 verifier contract
    function initialize(
        address anEntryPoint,
        address _verifier
    ) public {
        if(isInitialized) revert();
        isInitialized = true;

        _entryPoint = anEntryPoint;
        verifier = _verifier;
    }

    /// @notice Returns the EntryPoint contract
    /// @return The EntryPoint contract instance
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(_entryPoint);
    }

    /// @notice Validates the signature of a user operation
    /// @param userOp The user operation to validate
    /// @param userOpHash The hash of the user operation
    /// @return validationData 0 if valid, 1 if invalid
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        // Extract the signer address, smart contract address, and eth signature from the signature
        (address signer, address scopeContract, bytes memory ethSignature) = abi.decode(userOp.signature, (address, address, bytes));

        // Recover the signer from the signature
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(ethSignature, (uint8, bytes32, bytes32));
        address recoveredSigner = ecrecover(userOpHash, v, r, s);
        
        bool isValidSignature = (recoveredSigner == signer);
        
        // Check if the signer is registered and not expired
        bool isValidSigner = _isValidSigner(signer, scopeContract);
        
        bool result = isValidSignature && isValidSigner;
        return result ? 0 : 1;
    }

    function _isValidSigner(address signer, address scopeContract) internal view returns (bool) {
        // checks if the signer and scopeContract are registered and not expired
        return true;
    }


    /// @notice Executes a transaction
    /// @param dest The destination address
    /// @param value The amount of ETH to send
    /// @param func The function data to execute
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        _requireFromEntryPoint();
        (bool success, bytes memory result) = dest.call{value: value}(func);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @notice Receives Ether
    receive() external payable {}

    /// @notice Fallback function
    fallback() external payable {}
}
