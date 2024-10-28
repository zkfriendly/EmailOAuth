// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "./EmailAuthBase.sol";

/// @title EmailWalletFactory: Contract for creating email wallets.
contract EmailWalletFactory is EmailAuthBase {

    event EmailWalletCreated(
        address indexed emailAuthAddr,
        address indexed emailAccountAddr
    );

    constructor(
        address _verifierAddr,
        address _dkimAddr,
        address _emailAuthImplementationAddr
    ) EmailAuthBase(_verifierAddr, _dkimAddr, _emailAuthImplementationAddr) {}

    /// @notice Returns the version ID of the EmailWalletFactory contract.
    /// @return string A string representing the version ID.
    function versionId() public pure override returns (string memory) {
        return "EMAIL_WALLET_FACTORY_2.0";
    }

    /// @notice Returns a two-dimensional array of strings representing the command templates.
    /// @return string[][] A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function commandTemplates() public pure override returns (string[][] memory) {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](1);
        templates[0][0] = "CreateEmailAccount";
        return templates;
    }

    /// @notice Processes an email authentication message and executes the corresponding command.
    /// @dev This function deploys a new EmailAuth proxy if it doesn't exist, initializes it, and authenticates the email.
    /// @dev It then executes the command specified by the templateIdx.
    /// @param emailAuthMsg The email authentication message containing proof and command details.
    /// @param templateIdx The index of the command template to be executed.
    function commandEntryPoint(
        EmailAuthMsg memory emailAuthMsg,
        uint templateIdx
    ) public {
        EmailAuth emailAuth = getOrCreateEmailAuth(emailAuthMsg, templateIdx);
        emailAuth.authEmail(emailAuthMsg);

        if (templateIdx == 0) { // create email account
            emit EmailWalletCreated(address(emailAuth), address(this));
        } else {
            revert("invalid templateIdx");
        }
    }
}