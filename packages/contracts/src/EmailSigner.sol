// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "./EmailAuthBase.sol";

/// @title EmailSigner: Contract for signing emails.
contract EmailSigner is EmailAuthBase {

    event HashSigned(
        address indexed emailAuthAddr,
        bytes32 indexed hash
    );

    constructor(
        address _verifierAddr,
        address _dkimAddr,
        address _emailAuthImplementationAddr
    ) EmailAuthBase(_verifierAddr, _dkimAddr, _emailAuthImplementationAddr) {}

    function versionId() public pure override returns (string memory) {
        return "EMAIL_SIGNER";
    }

    /// @notice Returns a two-dimensional array of strings representing the command templates.
    /// @return string[][] A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function commandTemplates() public pure override returns (string[][] memory) {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](2);
        templates[0][0] = "SignHash";
        templates[0][1] = "{uint}";
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

        if (templateIdx == 0) { // sign hash
            uint hash = abi.decode(emailAuthMsg.commandParams[0], (uint));
            emit HashSigned(address(emailAuth), bytes32(hash));
        } else {
            revert("invalid templateIdx");
        }
    }
}
