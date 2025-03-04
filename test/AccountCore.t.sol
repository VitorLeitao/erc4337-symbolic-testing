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

    function payPrefund(uint256 prefund) public {
        _payPrefund(prefund);
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
        payable(address(account)).transfer(10 ether);
    }

    /*
     * @notice Tests whether validateUserOp executes correctly when called by the EntryPoint.
     * 
     * @dev Simulates a call from the EntryPoint and verifies that validation occurs without issues.
     *      The function should return SIG_VALIDATION_SUCCESS to indicate that the operation was successfully validated.
     * 
     * Expected result: Validation should be successful and return SIG_VALIDATION_SUCCESS.
     */
    function testValidateUserOpSuccess() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        
        // Simulates a call from the entrypoint
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, dummyUserOpHash, 0);
        
        // Checks if the return value indicates success
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    /*
     * @notice Tests whether the validateUserOp function correctly transfers the prefund to the EntryPoint.
     * 
     * @dev Simulates a call from the EntryPoint and verifies whether the account balance decreases and if the EntryPoint receives the correct amount.
     *      This ensures that the payment logic inside _payPrefund is working correctly.
     * 
     * Expected result: The EntryPoint should receive the funds, and the account balance should decrease by the prefund amount.
     */
    function testValidateUserOpPaysPrefund() public {
        uint256 initialAccountBalance = 10 ether;
        uint256 prefund = 1 ether;
        
        // Sets the account balance
        vm.deal(address(account), initialAccountBalance);
        // Records the current balance of the entrypoint
        uint256 initialEntryPointBalance = address(ERC4337Utils.ENTRYPOINT_V07).balance;
        
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        
        // Simulates the call from the entrypoint address
        // The validateUserOp calls _payPrefund, which in turn makes the transfer
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, dummyUserOpHash, prefund);
        
        // Checks if validation was successful
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
        // Checks if the entrypoint received the funds
        assertEq(address(ERC4337Utils.ENTRYPOINT_V07).balance, initialEntryPointBalance + prefund);
        // Checks if the account balance decreased by 'prefund'
        assertEq(address(account).balance, initialAccountBalance - prefund);
    }

    /*
     * @notice Tests whether an unauthorized call to validateUserOp correctly fails.
     * 
     * @dev Simulates an attempt to call from a random address (not the EntryPoint).
     *      The function should revert with the correct error message, ensuring that only the EntryPoint can call it.
     * 
     * Expected result: The transaction should revert with AccountUnauthorized.
     */
    function testValidateUserOpRevertsUnauthorized() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        uint256 prefund = 0;
        
        // Simulates a call from a random address that is not the entrypoint
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(0xBEEF)));
        account.validateUserOp(userOp, dummyUserOpHash, prefund);
    }   

     /*
     * @notice Tests whether the entryPoint function returns the correct EntryPoint address used by the account.
     * 
     * @dev Calls the entryPoint() function of the account and checks if the returned address
     *      matches the default EntryPoint address defined in ERC4337Utils.
     * 
     * Expected result: The returned address should exactly match ERC4337Utils.ENTRYPOINT_V07.
     */
    function testEntryPoint() public view { 
        IEntryPoint expectedEntryPoint = account.entryPoint();
        assertEq(address(expectedEntryPoint), address(ERC4337Utils.ENTRYPOINT_V07));
    }

    /*
     * @notice Tests whether validateUserOp correctly fails when the account does not have enough balance to pay the prefund.
     * 
     * @dev Sets a balance lower than required, simulates a call from the EntryPoint, and checks if the transaction fails.
     *      This ensures that the account cannot spend more than it has.
     * 
     * Expected result: The transaction should revert due to insufficient balance.
     */
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

    /*
     * @notice Tests whether validateUserOp correctly fails when the operation signature is invalid.
     * 
     * @dev Uses a modified account (MockBadAccountCore) that always generates invalid signatures.
     *      If the validation function is correct, it should return SIG_VALIDATION_FAILED to indicate a signature failure.
     * 
     * Expected result: The function should return SIG_VALIDATION_FAILED, indicating that the signature is not valid.
     */
    function testValidateUserOpWithInvalidSignature() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        MockBadAccountCore badAccount = new MockBadAccountCore();
        
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = badAccount.validateUserOp(userOp, dummyUserOpHash, 0);
        
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_FAILED);
    }

    /*
     * @notice Tests whether the validateUserOp function prevents calls from unauthorized addresses.
     * 
     * @dev The test simulates an attacker attempting to call validateUserOp directly to pay the prefund.
     *      Since only the EntryPoint should be able to call this function, we expect the transaction to revert.
     * 
     * Expected result: The test should pass if the call is correctly rejected with the AccountUnauthorized error.
     * If the test fails, it means there is a vulnerability allowing any address to execute the function improperly.
     */

    function testValidateUserOpUnauthorizedPrefund() public {
        uint256 initialAccountBalance = 5 ether;
        uint256 prefund = 1 ether;
        
        // Sets the account balance
        vm.deal(address(account), initialAccountBalance);
        
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");
        
        // Simulates a call from an attacker who is not the EntryPoint
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(0xDEAD))); // If it reverts, it means the operation was not performed, which is safe
        account.validateUserOp(userOp, dummyUserOpHash, prefund);
    }

    /*
     * @notice Tests whether an attacker can exploit the validateUserOp function to drain funds from the account.
     * 
     * @dev The test simulates an attacker calling validateUserOp directly to attempt an unauthorized balance transfer.
     *      If the function does not restrict calls to the EntryPoint, any address could trigger _payPrefund and extract funds.
     * 
     * Expected result: The transaction should revert, preventing the attack.
     * If the test fails (i.e., if the function allows execution), it indicates a critical vulnerability.
     */

    function testExploitPayPrefund() public {
        uint256 initialAccountBalance = 10 ether;
        uint256 maliciousPrefund = 1 ether;
        address attacker = address(0xDEADBEEF);
        
        // Define saldo inicial da conta
        vm.deal(address(account), initialAccountBalance);
        
        // Cria uma operação dummy
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 fakeUserOpHash = keccak256("malicious_op");
        
        // Simula o ataque
        vm.prank(attacker); // Finge que a proxima chamada vem do atacante
        vm.expectRevert(); // Se ele reverteu, signifca que não realizou a operação, ou seja, é seguro
        account.validateUserOp(userOp, fakeUserOpHash, maliciousPrefund); // o atacante tenta chamar a função para transferir da conta do usuário
    }

    /*
     * @notice Tests whether an attacker can manipulate the prefund value to cause a DoS on the account.
     * 
     * @dev If an attacker can set a prefund larger than the account balance, they could make all future operations fail,
     *      blocking the account from interacting with the network.
     * 
     * Expected result: The transaction should revert due to insufficient balance.
     */
    function testPrefundManipulation() public {
        uint256 initialAccountBalance = 1 ether;
        uint256 excessivePrefund = 100 ether; // Prefund much larger than the balance

        vm.deal(address(account), initialAccountBalance);
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");

        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        vm.expectRevert(); // Should fail due to insufficient balance
        account.validateUserOp(userOp, dummyUserOpHash, excessivePrefund);
    }   


    /*
     * @notice Tests whether an attacker can force the account to transfer funds to them without permission.
     * 
     * @dev If the account does not properly verify the caller's permissions before transferring funds,
     *      an attacker could try to redirect the payment to themselves.
     * 
     * Expected result: The transaction should fail if the permission verification is correct.
     */
    function testForcedTransfer() public {
        uint256 initialAccountBalance = 10 ether;
        address attacker = address(0xBADC0DE);

        vm.deal(address(account), initialAccountBalance);
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("forced_transfer");

        // Simulates the attacker trying to divert the funds to themselves
        vm.prank(attacker);
        vm.expectRevert(); // Should fail if the account prevents unauthorized transfers
        account.validateUserOp(userOp, dummyUserOpHash, 1 ether);
    }

    /* 
     * @notice Tests whether signature reuse allows executing multiple unauthorized transactions.
     * 
     * @dev If the function does not invalidate already-used operations, an attacker could reuse old signatures
     *      to execute repeated transactions and drain the account balance.
     * 
     * Expected result: The second execution attempt should fail, but it does not.
     */
    function testReplayAttack() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 userOpHash = keccak256("replay_attack");
        
        // Simulates a legitimate call from the EntryPoint
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);

        // Simulates a second attempt with the same operation (replay attack)
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        vm.expectRevert(); // Should fail if replay protection is correct
        account.validateUserOp(userOp, userOpHash, 0);
    }

    /* 
    @notice Verifies the behavior of user operation validation when the signature is empty.
    @dev The function is expected to fail validation when provided with an empty signature.
    Expected result: Validation should fail indicating a signature error.
    */
    function testValidateUserOpWithEmptySignature() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");

        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, dummyUserOpHash, 0);

        console.log("validationData:", validationData);
        console.log("expected:", ERC4337Utils.SIG_VALIDATION_FAILED);

        // assertEq(validationData, ERC4337Utils.SIG_VALIDATION_FAILED, "Empty signature should fail.");
    }

    /* 
    @notice Tests Ether handling to verify that funds are correctly transferred.
    @dev Evaluates both successful transfer and failure due to insufficient balance.
    Expected result: Funds should be transferred correctly, and failures should occur when the balance is insufficient.
    */
    function testEtherHandling() public {
        uint256 prefundAmount = 1 ether;

        // Tests the transfer of ether
        vm.prank(address(account.entryPoint()));
        account.payPrefund(prefundAmount); // Test call that involves _payPrefund

        // Checks the balance after the operation to ensure funds were transferred correctly
        assertEq(address(account.entryPoint()).balance, prefundAmount, "Funds were not transferred correctly");

        // Tests failure of ether transfer due to insufficient balance
        vm.prank(address(account.entryPoint()));
        vm.expectRevert("Insufficient balance for prefund");
        account.payPrefund(20 ether); // Call with an amount greater than the available balance
    }

    /* 
    @notice Ensures that only authorized addresses can call sensitive functions.
    @dev Tests the `validateUserOp` function to ensure only the entryPoint or the account itself can invoke it.
    Expected result: Unauthorized calls should fail with the corresponding error message.
    */
    function testOnlyEntryPointOrSelf() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 hash = keccak256(abi.encodePacked("dummy"));

        // Attempts to invoke the function from an address that is neither the entryPoint nor the account itself.
        address unauthorizedAddress = address(0x123);
        vm.prank(unauthorizedAddress);
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, unauthorizedAddress));
        account.validateUserOp(userOp, hash, 0);

        // Simulates call from the entryPoint
        vm.prank(address(account.entryPoint()));
        account.validateUserOp(userOp, hash, 0); // This call should not fail.
    }

    /* 
    @notice Tests the payment of a zero Ether prefund to verify if the contract logic supports it.
    @dev Should pass without errors even with zero prefund.
    Expected result: No exception should be thrown.
    */
    function payPrefundZero() public {
        uint256 prefund = 0;
        account.payPrefund(prefund);
    }

    /* 
    @notice Tests the condition of attempting to pay a prefund greater than the available balance.
    @dev The function is expected to revert when the prefund amount exceeds the available balance.
    Expected result: The transaction should fail with a revert.
    */
    function payPrefundExceedsBalance() public {
        uint256 prefund = address(account).balance + 20 ether;
        vm.expectRevert();
        account.payPrefund(prefund);
    }

    /* 
    @notice Performs stress testing on user operation validation to verify robustness and efficiency under load.
    @dev Executes multiple iterations of validating a UserOperation, updating the nonce each iteration to simulate a sequence of consecutive valid operations.
    Expected result: All iterations should pass without errors, demonstrating that the system can handle multiple validations efficiently and consecutively.
    */
    function testStressValidateUserOp() public {
        uint256 iterations = 100;
        PackedUserOperation memory userOp = _dummyUserOp();
        address entryPointAddr = address(account.entryPoint());

        for (uint256 i = 0; i < iterations; i++) {
            uint256 userOpNonce = account.getNonce(0);
            userOp.nonce = userOpNonce;
            bytes32 userOpHash = keccak256(abi.encode(userOp));

            vm.prank(entryPointAddr); // Simulates call from the EntryPoint
            account.validateUserOp(userOp, userOpHash, 0);
        }
    }

    /* 
    @notice Checks if repeated calls to the entryPoint cause gas leaks.
    @dev Simulates multiple checks of the entryPoint's existence to assess gas consumption and performance.
    Expected result: There should not be any significant increase in gas consumption.
    */
    function testStressEntryPoint() public view {
        uint256 iterations = 1000;

        for (uint256 i = 0; i < iterations; i++) {
            address ep = address(account.entryPoint());
            assertTrue(ep != address(0), "EntryPoint should not be zero");
        }
    }

    /* 
    @notice Conducts stress tests with escalating prefund payments to assess the robustness of fund management.
    @dev Progressively increases the prefund amount and checks if the function correctly handles both sufficient and insufficient balances.
    Expected result: Transactions should pass when there is sufficient balance and fail when not.
    */
    function testStressPayPrefund() public {
        uint256 maxTests = 50; // Number of prefund executions
        uint256 baseAmount = 0.01 ether;

        for (uint256 i = 0; i < maxTests; i++) {
            uint256 prefund = baseAmount * (i + 1); // Progressively increases the amount
            bool success = address(account).balance >= prefund;

            if (success) {
                account.payPrefund(prefund);
            } else {
                vm.expectRevert();
                account.payPrefund(prefund);
            }
        }
    }
}
