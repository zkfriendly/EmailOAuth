// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
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

    /// @notice Returns a two-dimensional array of strings representing the command templates.
    /// @return string[][] A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function commandTemplates() public pure returns (string[][] memory) {
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
        address owner = address(this);
        address emailAuthAddr = computeEmailAuthAddress(
            owner,
            emailAuthMsg.proof.accountSalt
        );
        uint templateId = computeTemplateId(templateIdx);
        require(templateId == emailAuthMsg.templateId, "invalid template id");

        EmailAuth emailAuth;
        if (emailAuthAddr.code.length == 0) {
            require(
                emailAuthMsg.proof.isCodeExist == true,
                "isCodeExist must be true for the first email"
            );
            address proxyAddress = deployEmailAuthProxy(
                owner,
                emailAuthMsg.proof.accountSalt
            );
            require(
                proxyAddress == emailAuthAddr,
                "proxy address does not match with emailAuthAddr"
            );
            emailAuth = EmailAuth(proxyAddress);
            emailAuth.initDKIMRegistry(dkim());
            emailAuth.initVerifier(verifier());
            string[][] memory templates = commandTemplates();
            for (uint idx = 0; idx < templates.length; idx++) {
                emailAuth.insertCommandTemplate(
                    computeTemplateId(idx),
                    templates[idx]
                );
            }
        } else {
            emailAuth = EmailAuth((emailAuthAddr));
            require(
                emailAuth.controller() == address(this),
                "invalid controller"
            );
        }
        emailAuth.authEmail(emailAuthMsg);

        if (templateIdx == 0) { // create email account
            emit EmailWalletCreated(emailAuthAddr, owner);
        } else {
            revert("invalid templateIdx");
        }
    }
}
