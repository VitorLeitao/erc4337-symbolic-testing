// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/AccountCore.sol";
import "../utils/openzeppelin-contracts/contracts/interfaces/draft-IERC4337.sol";


// Instanciando uma AccountCore
contract MockAccountCore is AccountCore {
    function _signableUserOpHash(
        PackedUserOperation calldata /* userOp */, 
        bytes32 userOpHash
    ) internal pure override returns (bytes32) {
        return userOpHash;
    }

    function _rawSignatureValidation(
        bytes32 /* hash */, 
        bytes calldata /* signature */
    ) internal pure virtual override returns (bool) {
        return true;
    }

    function _payPrefund(uint256 prefund) internal override {
        require(address(this).balance >= prefund, "Insufficient balance for prefund");
        (bool success, ) = payable(address(entryPoint())).call{value: prefund}("");
        require(success, "Prefund transfer failed");
    }
}

contract MockBadAccountCore is MockAccountCore {
    function _rawSignatureValidation(
        bytes32 /* hash */, 
        bytes calldata /* signature */
    ) internal pure override returns (bool) {
        return false;
    }
}


// Conceito: Entrypoint:  Ele recebe, valida e encaminha as operações, garantindo que somente chamadas autorizadas possam executar funções sensíveis no contrato da conta, ou seja, o endereço das transferências será o dele;
// Conceito: UserOperation: UserOperation é uma representação abstrata de uma ação que o usuário deseja realizar, como uma transferência ou outra interação com um contrato
// Conceito: Nonce: Nonce é um valor único associado a uma operação, garantindo que ela seja única

contract AccountCoreTest is Test {
    MockAccountCore account;

    // Função auxiliar para criar uma operação dummy utilizando o construtor posicional
    function _dummyUserOp() internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation(
            address(0),
            0,
            "",
            "",
            0, // callGasLimit
            0, // verificationGasLimit
            0, // preVerificationGas
            "", // paymasterAndData (deve ser bytes)
            ""  // signature
        );
    }

    function setUp() public {
        account = new MockAccountCore();
    }

    function testValidateUserOpSuccess() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        
        // Simula a chamada vinda do entrypoint
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, dummyUserOpHash, 0);
        
        // Verifica se o retorno é o de sucesso
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    // Testa se a função _payPrefund repassa corretamente os fundos ao entrypoint
    function testValidateUserOpPaysPrefund() public {
        uint256 initialAccountBalance = 10 ether;
        uint256 prefund = 1 ether;
        
        // Define o saldo da conta
        vm.deal(address(account), initialAccountBalance);
        // Registra o saldo atual do entrypoint
        uint256 initialEntryPointBalance = address(ERC4337Utils.ENTRYPOINT_V07).balance;
        
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        
        // Simula a chamada vinda do endereço do entrypoint
        // O validateUserOp chama o _payPrefund, que por sua vez faz a transferência
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, dummyUserOpHash, prefund);
        
        // Verifica se a validação foi bem-sucedida
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
        // Verifica se o entrypoint recebeu os fundos
        assertEq(address(ERC4337Utils.ENTRYPOINT_V07).balance, initialEntryPointBalance + prefund);
        // Verifica se o saldo da conta diminuiu em 'prefund'
        assertEq(address(account).balance, initialAccountBalance - prefund);
    }

    // Testa se uma chamada de um endereço não autorizado reverte com o erro correto
    function testValidateUserOpRevertsUnauthorized() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        uint256 prefund = 0;
        
        // Simula uma chamada vinda de um endereço aleatório que não é o entrypoint
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(0xBEEF)));
        account.validateUserOp(userOp, dummyUserOpHash, prefund);
    }

    function testEntryPoint() public view { 
        IEntryPoint expectedEntryPoint = account.entryPoint();
        assertEq(address(expectedEntryPoint), address(ERC4337Utils.ENTRYPOINT_V07));
    }

    // Garante que a validação falha quando a conta não tem saldo suficiente para pagar o prefund.
    function testValidateUserOpFailsWithInsufficientBalance() public {
        uint256 initialAccountBalance = 0.5 ether;
        uint256 prefund = 1 ether;
        vm.deal(address(account), initialAccountBalance);
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        vm.expectRevert(); // Sem mensagem específica, pois depende da falha no call
        account.validateUserOp(userOp, dummyUserOpHash, prefund);
    }

    // Simula uma assinatura inválida e verifica se a validação falha corretamente.
    function testValidateUserOpWithInvalidSignature() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        MockBadAccountCore badAccount = new MockBadAccountCore();
        
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = badAccount.validateUserOp(userOp, dummyUserOpHash, 0);
        
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_FAILED);
    }
}
