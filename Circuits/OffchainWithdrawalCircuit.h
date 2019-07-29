#ifndef _OFFCHAINWITHDRAWALCIRCUIT_H_
#define _OFFCHAINWITHDRAWALCIRCUIT_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "../Utils/Utils.h"
#include "../Gadgets/AccountGadgets.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/subadd.hpp"

using namespace ethsnarks;

namespace Loopring
{

class OffchainWithdrawalGadget : public GadgetT
{
public:

    const Constants& constants;

    libsnark::dual_variable_gadget<FieldT> accountID;
    libsnark::dual_variable_gadget<FieldT> tokenID;
    libsnark::dual_variable_gadget<FieldT> amountRequested;
    libsnark::dual_variable_gadget<FieldT> fee;

    libsnark::dual_variable_gadget<FieldT> walletAccountID;
    libsnark::dual_variable_gadget<FieldT> feeTokenID;
    FloatGadget fFee;
    EnsureAccuracyGadget ensureAccuracyFee;
    PercentageGadget walletSplitPercentage;

    BalanceState balanceFBefore;
    BalanceState balanceBefore;
    libsnark::dual_variable_gadget<FieldT> nonce_before;
    UnsafeAddGadget nonce_after;
    AccountState accountBefore;

    BalanceState balanceWalletBefore;
    AccountState accountWalletBefore;

    VariableT balanceF_O_before;
    VariableT tradingHistoryRootF_O;

    MulDivGadget feeToWallet;
    UnsafeSubGadget feeToOperator;
    subadd_gadget feePaymentWallet;
    subadd_gadget feePaymentOperator;
    MinGadget amountToWithdraw;
    FloatGadget amountWithdrawn;
    EnsureAccuracyGadget ensureAccuracyAmountWithdrawn;

    SubGadget balance_after;

    BalanceState balanceFAfter;
    UpdateBalanceGadget updateBalanceF_A;
    BalanceState balanceAfter;
    UpdateBalanceGadget updateBalance_A;
    AccountState accountAfter;
    UpdateAccountGadget updateAccount_A;

    BalanceState balanceWalletAfter;
    UpdateBalanceGadget updateBalance_W;
    AccountState accountWalletAfter;
    UpdateAccountGadget updateAccount_W;

    UpdateBalanceGadget updateBalanceF_O;

    Poseidon_gadget_T<11, 1, 6, 53, 9, 1> hash;
    SignatureVerifier signatureVerifier;

    OffchainWithdrawalGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& _constants,
        const VariableT& accountsMerkleRoot,
        const VariableT& operatorBalancesRoot,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        constants(_constants),

        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amountRequested(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amountRequested")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        walletAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".walletAccountID")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
        walletSplitPercentage(pb, constants, FMT(prefix, ".walletSplitPercentage")),

        ensureAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, FMT(prefix, ".ensureAccuracyFee")),

        // User
        balanceFBefore({
            make_variable(pb, FMT(prefix, ".beforeF.balance")),
            make_variable(pb, FMT(prefix, ".beforeF.tradingHistory"))
        }),
        balanceBefore({
            make_variable(pb, FMT(prefix, ".before.balance")),
            make_variable(pb, FMT(prefix, ".before.tradingHistory"))
        }),
        nonce_before(pb, NUM_BITS_NONCE, FMT(prefix, ".nonce_before")),
        // Increase nonce by 1
        nonce_after(pb, nonce_before.packed, constants.one, FMT(prefix, ".nonce_after")),
        accountBefore({
            make_variable(pb, FMT(prefix, ".publicKeyX")),
            make_variable(pb, FMT(prefix, ".publicKeyY")),
            nonce_before.packed,
            make_variable(pb, FMT(prefix, ".before.balancesRoot"))
        }),

        // Wallet
        balanceWalletBefore({
            make_variable(pb, FMT(prefix, ".beforeWallet.balance")),
            constants.emptyTradeHistory
        }),
        accountWalletBefore({
            make_variable(pb, FMT(prefix, ".walletPublicKeyX")),
            make_variable(pb, FMT(prefix, ".walletPublicKeyY")),
            make_variable(pb, FMT(prefix, ".nonce")),
            make_variable(pb, FMT(prefix, ".before.balancesRoot"))
        }),

        // Operator
        balanceF_O_before(make_variable(pb, FMT(prefix, ".balanceF_O_before"))),
        tradingHistoryRootF_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_O"))),

        // Split the fee between wallet and operator
        feeToWallet(pb, constants, fFee.value(), walletSplitPercentage.value.packed, constants._100, FMT(prefix, ".feeToWallet")),
        feeToOperator(pb, fFee.value(), feeToWallet.result(), FMT(prefix, ".feeToOperator")),
        // Calculate the balances after fee payment of the wallet and operator
        feePaymentWallet(pb, NUM_BITS_AMOUNT, balanceFBefore.balance, balanceWalletBefore.balance, feeToWallet.result(), FMT(prefix, ".feePaymentWallet")),
        feePaymentOperator(pb, NUM_BITS_AMOUNT, feePaymentWallet.X, balanceF_O_before, feeToOperator.result(), FMT(prefix, ".feePaymentOperator")),

        // Calculate how much can be withdrawn
        amountToWithdraw(pb, amountRequested.packed, balanceBefore.balance, NUM_BITS_AMOUNT, FMT(prefix, ".min(amountRequested, balance)")),
        amountWithdrawn(pb, constants, Float28Encoding, FMT(prefix, ".amountWithdrawn")),
        ensureAccuracyAmountWithdrawn(pb, amountWithdrawn.value(), amountToWithdraw.result(), Float28Accuracy, FMT(prefix, ".ensureAccuracyAmountRequested")),

        // Calculate new balance
        balance_after(pb, balanceBefore.balance, amountWithdrawn.value(), NUM_BITS_MAX_VALUE - 1, FMT(prefix, ".balance_after")),

        // Update User
        balanceFAfter({
            feePaymentOperator.X,
            balanceFBefore.tradingHistory
        }),
        updateBalanceF_A(pb, accountBefore.balancesRoot, feeTokenID.bits, balanceFBefore, balanceFAfter, FMT(prefix, ".updateBalanceF_A")),
        balanceAfter({
            balance_after.result(),
            balanceBefore.tradingHistory
        }),
        updateBalance_A(pb, updateBalanceF_A.getNewRoot(), tokenID.bits, balanceBefore, balanceAfter, FMT(prefix, ".updateBalance_A")),
        accountAfter({
            accountBefore.publicKeyX,
            accountBefore.publicKeyY,
            nonce_after.result(),
            updateBalance_A.getNewRoot()
        }),
        updateAccount_A(pb, accountsMerkleRoot, accountID.bits, accountBefore, accountAfter, FMT(prefix, ".updateAccount_A")),

        // Update Wallet
        balanceWalletAfter({
            feePaymentWallet.Y,
            balanceWalletBefore.tradingHistory
        }),
        updateBalance_W(pb, accountWalletBefore.balancesRoot, feeTokenID.bits, balanceWalletBefore, balanceWalletAfter, FMT(prefix, ".updateBalance_W")),
        accountWalletAfter({
            accountWalletBefore.publicKeyX,
            accountWalletBefore.publicKeyY,
            accountWalletBefore.nonce,
            updateBalance_W.getNewRoot()
        }),
        updateAccount_W(pb, updateAccount_A.result(), walletAccountID.bits, accountWalletBefore, accountWalletAfter, FMT(prefix, ".updateAccount_W")),

        // Update Operator
        updateBalanceF_O(pb, operatorBalancesRoot, feeTokenID.bits,
                         {balanceF_O_before, tradingHistoryRootF_O},
                         {feePaymentOperator.Y, tradingHistoryRootF_O},
                         FMT(prefix, ".updateBalanceF_O")),

        // Signature
        hash(pb, var_array({
            blockExchangeID,
            accountID.packed,
            tokenID.packed,
            amountRequested.packed,
            walletAccountID.packed,
            feeTokenID.packed,
            fee.packed,
            walletSplitPercentage.value.packed,
            nonce_before.packed
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, jubjub::VariablePointT(accountBefore.publicKeyX, accountBefore.publicKeyY),
                          hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_W.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceF_O.getNewRoot();
    }

    const std::vector<VariableArrayT> getApprovedWithdrawalData() const
    {
        return {tokenID.bits,
                accountID.bits,
                amountWithdrawn.bits()};
    }

    const std::vector<VariableArrayT> getDataAvailabilityData() const
    {
        return {constants.accountPadding, walletAccountID.bits,
                feeTokenID.bits,
                fFee.bits(),
                constants.padding_0, walletSplitPercentage.value.bits};
    }

    void generate_r1cs_witness(const OffchainWithdrawal& withdrawal)
    {
        accountID.bits.fill_with_bits_of_field_element(pb, withdrawal.accountUpdate_A.accountID);
        accountID.generate_r1cs_witness_from_bits();
        tokenID.bits.fill_with_bits_of_field_element(pb, withdrawal.balanceUpdateW_A.tokenID);
        tokenID.generate_r1cs_witness_from_bits();
        walletAccountID.bits.fill_with_bits_of_field_element(pb, withdrawal.accountUpdate_W.accountID);
        walletAccountID.generate_r1cs_witness_from_bits();
        feeTokenID.bits.fill_with_bits_of_field_element(pb, withdrawal.balanceUpdateF_A.tokenID);
        feeTokenID.generate_r1cs_witness_from_bits();
        fee.bits.fill_with_bits_of_field_element(pb, withdrawal.fee);
        fee.generate_r1cs_witness_from_bits();
        fFee.generate_r1cs_witness(toFloat(withdrawal.fee, Float16Encoding));
        walletSplitPercentage.generate_r1cs_witness(withdrawal.walletSplitPercentage);
        amountRequested.bits.fill_with_bits_of_field_element(pb, withdrawal.amountRequested);
        amountRequested.generate_r1cs_witness_from_bits();

        ensureAccuracyFee.generate_r1cs_witness();

        // User
        pb.val(balanceFBefore.tradingHistory) = withdrawal.balanceUpdateF_A.before.tradingHistoryRoot;
        pb.val(balanceFBefore.balance) = withdrawal.balanceUpdateF_A.before.balance;
        pb.val(balanceBefore.tradingHistory) = withdrawal.balanceUpdateW_A.before.tradingHistoryRoot;
        pb.val(balanceBefore.balance) = withdrawal.balanceUpdateW_A.before.balance;
        pb.val(balanceAfter.balance) = withdrawal.balanceUpdateW_A.after.balance;
        pb.val(accountBefore.publicKeyX) = withdrawal.accountUpdate_A.before.publicKey.x;
        pb.val(accountBefore.publicKeyY) = withdrawal.accountUpdate_A.before.publicKey.y;
        pb.val(accountBefore.balancesRoot) = withdrawal.accountUpdate_A.before.balancesRoot;
        nonce_before.bits.fill_with_bits_of_field_element(pb, withdrawal.accountUpdate_A.before.nonce);
        nonce_before.generate_r1cs_witness_from_bits();
        nonce_after.generate_r1cs_witness();

        // Wallet
        pb.val(balanceWalletBefore.balance) = withdrawal.balanceUpdateF_W.before.balance;
        pb.val(accountWalletBefore.publicKeyX) = withdrawal.accountUpdate_W.before.publicKey.x;
        pb.val(accountWalletBefore.publicKeyY) = withdrawal.accountUpdate_W.before.publicKey.y;
        pb.val(accountWalletBefore.balancesRoot) = withdrawal.accountUpdate_W.before.balancesRoot;
        pb.val(accountWalletBefore.nonce) = withdrawal.accountUpdate_W.before.nonce;

        // Operator
        pb.val(balanceF_O_before) = withdrawal.balanceUpdateF_O.before.balance;
        pb.val(tradingHistoryRootF_O) = withdrawal.balanceUpdateF_O.before.tradingHistoryRoot;

        // Fee payments calculations
        feeToWallet.generate_r1cs_witness();
        feeToOperator.generate_r1cs_witness();
        feePaymentWallet.generate_r1cs_witness();
        feePaymentOperator.generate_r1cs_witness();
        amountToWithdraw.generate_r1cs_witness();
        amountWithdrawn.generate_r1cs_witness(toFloat((pb.val(balanceBefore.balance) - pb.val(balanceAfter.balance)), Float28Encoding));
        ensureAccuracyAmountWithdrawn.generate_r1cs_witness();

        // Calculate new balance
        balance_after.generate_r1cs_witness();

        // Update User
        updateBalanceF_A.generate_r1cs_witness(withdrawal.balanceUpdateF_A.proof);
        updateBalance_A.generate_r1cs_witness(withdrawal.balanceUpdateW_A.proof);
        updateAccount_A.generate_r1cs_witness(withdrawal.accountUpdate_A.proof);

        // Update Wallet
        updateBalance_W.generate_r1cs_witness(withdrawal.balanceUpdateF_W.proof);
        updateAccount_W.generate_r1cs_witness(withdrawal.accountUpdate_W.proof);

        // Update operator
        updateBalanceF_O.generate_r1cs_witness(withdrawal.balanceUpdateF_O.proof);

        // Check signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(withdrawal.signature);
    }

    void generate_r1cs_constraints()
    {
        accountID.generate_r1cs_constraints(true);
        tokenID.generate_r1cs_constraints(true);
        walletAccountID.generate_r1cs_constraints(true);
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);
        fFee.generate_r1cs_constraints();
        ensureAccuracyFee.generate_r1cs_constraints();
        nonce_before.generate_r1cs_constraints(true);
        nonce_after.generate_r1cs_constraints();
        walletSplitPercentage.generate_r1cs_constraints();

        feeToWallet.generate_r1cs_constraints();
        feeToOperator.generate_r1cs_constraints();

        feePaymentWallet.generate_r1cs_constraints();
        feePaymentOperator.generate_r1cs_constraints();

        amountRequested.generate_r1cs_constraints(true);

        amountWithdrawn.generate_r1cs_constraints();
        ensureAccuracyAmountWithdrawn.generate_r1cs_constraints();

        balance_after.generate_r1cs_constraints();

        updateBalance_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();

        updateBalanceF_A.generate_r1cs_constraints();
        updateBalance_W.generate_r1cs_constraints();
        updateAccount_W.generate_r1cs_constraints();
        updateBalanceF_O.generate_r1cs_constraints();

        // Check signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }
};

class OffchainWithdrawalCircuit : public GadgetT
{
public:
    jubjub::Params params;

    bool onchainDataAvailability;
    unsigned int numWithdrawals;
    std::vector<OffchainWithdrawalGadget> withdrawals;

    PublicDataGadget publicData;

    Constants constants;

    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;

    libsnark::dual_variable_gadget<FieldT> operatorAccountID;
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot_before;
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    OffchainWithdrawalCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),

        constants(pb, FMT(prefix, ".constants")),

        exchangeID(pb, 32, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),

        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),
        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, 0, FMT(prefix, ".nonce"))),
        balancesRoot_before(make_variable(pb, 0, FMT(prefix, ".balancesRoot_before")))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numWithdrawals)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numWithdrawals = numWithdrawals;

        constants.generate_r1cs_witness();

        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);

        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        for (size_t j = 0; j < numWithdrawals; j++)
        {
            VariableT withdrawalAccountsRoot = (j == 0) ? merkleRootBefore.packed : withdrawals.back().getNewAccountsRoot();
            VariableT withdrawalOperatorBalancesRoot = (j == 0) ? balancesRoot_before : withdrawals.back().getNewOperatorBalancesRoot();
            withdrawals.emplace_back(
                pb,
                params,
                constants,
                withdrawalAccountsRoot,
                withdrawalOperatorBalancesRoot,
                exchangeID.packed,
                std::string("withdrawals_") + std::to_string(j)
            );
            withdrawals.back().generate_r1cs_constraints();
        }

        operatorAccountID.generate_r1cs_constraints(true);

        // Update the operator account
        updateAccount_O.reset(new UpdateAccountGadget(pb, withdrawals.back().getNewAccountsRoot(), operatorAccountID.bits,
            {publicKey.x, publicKey.y, nonce, balancesRoot_before},
            {publicKey.x, publicKey.y, nonce, withdrawals.back().getNewOperatorBalancesRoot()},
            FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Store the approved data for all withdrawals
        for (auto& withdrawal : withdrawals)
        {
            publicData.add(withdrawal.getApprovedWithdrawalData());
        }

        // Data availability
        if (onchainDataAvailability)
        {
            publicData.add(constants.accountPadding);
            publicData.add(operatorAccountID.bits);
            for (auto& withdrawal : withdrawals)
            {
                publicData.add(withdrawal.getDataAvailabilityData());
            }
        }

        // Check the input hash
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numWithdrawals) << "/offchain withdrawal)" << std::endl;
    }

    bool generateWitness(const OffchainWithdrawalBlock& block)
    {
        constants.generate_r1cs_witness();

        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();

        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();

        // Operator
        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();
        pb.val(publicKey.x) = block.accountUpdate_O.before.publicKey.x;
        pb.val(publicKey.y) = block.accountUpdate_O.before.publicKey.y;
        pb.val(nonce) = block.accountUpdate_O.before.nonce;
        pb.val(balancesRoot_before) = block.accountUpdate_O.before.balancesRoot;

        for(unsigned int i = 0; i < block.withdrawals.size(); i++)
        {
            withdrawals[i].generate_r1cs_witness(block.withdrawals[i]);
        }

        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        publicData.generate_r1cs_witness();

        return true;
    }
};

}

#endif
