// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title EmailAccountBase: Base contract for signing arbitrary hashes using an email account.
contract EmailAccountBase {
    address public verifierAddr;
    address public dkimAddr;
    address public emailAuthImplementationAddr;

    mapping(uint256 => bool) public isSigned;

    event SignHashCommand(
        address indexed emailAuthAddr,
        uint256 indexed hash
    );

    constructor(
        address _verifierAddr,
        address _dkimAddr,
        address _emailAuthImplementationAddr
    ) {
        verifierAddr = _verifierAddr;
        dkimAddr = _dkimAddr;
        emailAuthImplementationAddr = _emailAuthImplementationAddr;
    }

    /// @notice Returns the address of the verifier contract.
    /// @dev This function is virtual and can be overridden by inheriting contracts.
    /// @return address The address of the verifier contract.
    function verifier() public view virtual returns (address) {
        return verifierAddr;
    }

    /// @notice Returns the address of the DKIM contract.
    /// @dev This function is virtual and can be overridden by inheriting contracts.
    /// @return address The address of the DKIM contract.
    function dkim() public view virtual returns (address) {
        return dkimAddr;
    }

    /// @notice Returns the address of the email auth contract implementation.
    /// @dev This function is virtual and can be overridden by inheriting contracts.
    /// @return address The address of the email authentication contract implementation.
    function emailAuthImplementation() public view virtual returns (address) {
        return emailAuthImplementationAddr;
    }

    /// @notice Computes the address for email auth contract using the CREATE2 opcode.
    /// @dev This function utilizes the `Create2` library to compute the address. The computation uses a provided account address to be recovered, account salt,
    /// and the hash of the encoded ERC1967Proxy creation code concatenated with the encoded email auth contract implementation
    /// address and the initialization call data. This ensures that the computed address is deterministic and unique per account salt.
    /// @param accountSalt A bytes32 salt value defined as a hash of the guardian's email address and an account code. This is assumed to be unique to a pair of the guardian's email address and the wallet address to be recovered.
    /// @return address The computed address.
    function computeEmailAuthAddress(
        bytes32 accountSalt
    ) public view returns (address) {
        return
            Create2.computeAddress(
                accountSalt,
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            emailAuthImplementation(),
                            abi.encodeCall(
                                EmailAuth.initialize,
                                (address(this), accountSalt, address(this))
                            )
                        )
                    )
                )
            );
    }

    /// @notice Deploys a new proxy contract for email authentication.
    /// @dev This function uses the CREATE2 opcode to deploy a new ERC1967Proxy contract with a deterministic address.
    /// @param accountSalt A bytes32 salt value used to ensure the uniqueness of the deployed proxy address.
    /// @return address The address of the newly deployed proxy contract.
    function deployEmailAuthProxy(
        bytes32 accountSalt
    ) internal returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy{salt: accountSalt}(
            emailAuthImplementation(),
            abi.encodeCall(
                EmailAuth.initialize,
                (address(this), accountSalt, address(this))
            )
        );
        return address(proxy);
    }

    /// @notice Calculates a unique command template ID for template provided by this contract.
    /// @dev Encodes the email account recovery version ID, "EXAMPLE", and the template index,
    /// then uses keccak256 to hash these values into a uint ID.
    /// @param templateIdx The index of the command template.
    /// @return uint The computed uint ID.
    function computeTemplateId(uint templateIdx) public pure returns (uint) {
        return uint256(keccak256(abi.encode("EXAMPLE", templateIdx)));
    }

    /// @notice Returns a two-dimensional array of strings representing the command templates.
    /// @return string[][] A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function commandTemplates() public pure returns (string[][] memory) {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](2);
        templates[0][0] = "SignHash";
        templates[0][1] = "{uint}";
        return templates;
    }

    /// @notice Processes an email authentication message and executes the corresponding command.
    /// @dev This function deploys a new EmailAuth proxy if it doesn't exist, initializes it, and authenticates the email.
    /// @dev It then executes the command specified by the templateIdx. Currently, only the SignHash command (templateIdx 0) is supported.
    /// @param emailAuthMsg The email authentication message containing proof and command details.
    /// @param templateIdx The index of the command template to be executed.
    function entryPoint(
        EmailAuthMsg memory emailAuthMsg,
        uint templateIdx
    ) public {
        address emailAuthAddr = computeEmailAuthAddress(
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
            emailAuth = EmailAuth(payable(address(emailAuthAddr)));
            require(
                emailAuth.controller() == address(this),
                "invalid controller"
            );
        }
        emailAuth.authEmail(emailAuthMsg);

        if (templateIdx == 0) { // SignHash command
            uint256 hash = abi.decode(emailAuthMsg.commandParams[0], (uint256));
            isSigned[hash] = true;
            emit SignHashCommand(emailAuthAddr, hash);
        } else {
            revert("invalid templateIdx");
        }
    }
}
