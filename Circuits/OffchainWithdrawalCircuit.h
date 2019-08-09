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

    // User state
    BalanceState balanceFBefore;
    BalanceState balanceBefore;
    AccountState accountBefore;
    // Operator state
    VariableT balanceF_O_before;
    VariableT tradingHistoryRootF_O;

    // Inputs
    libsnark::dual_variable_gadget<FieldT> accountID;
    libsnark::dual_variable_gadget<FieldT> tokenID;
    libsnark::dual_variable_gadget<FieldT> amountRequested;
    libsnark::dual_variable_gadget<FieldT> feeTokenID;
    libsnark::dual_variable_gadget<FieldT> fee;
    libsnark::dual_variable_gadget<FieldT> label;

    // Fee as float
    FloatGadget fFee;
    RequireAccuracyGadget requireAccuracyFee;

    // Fee payment from the user to the operator
    subadd_gadget feePayment;

    // Calculate how much can be withdrawn
    MinGadget amountToWithdraw;
    FloatGadget amountWithdrawn;
    RequireAccuracyGadget requireAccuracyAmountWithdrawn;

    // Calculate the new balance
    UnsafeSubGadget balance_after;

    // Increase the nonce of the user by 1
    AddGadget nonce_after;

    // Update User
    UpdateBalanceGadget updateBalanceF_A;
    UpdateBalanceGadget updateBalance_A;
    UpdateAccountGadget updateAccount_A;

    // Update Operator
    UpdateBalanceGadget updateBalanceF_O;

    // Signature
    Poseidon_gadget_T<9, 1, 6, 53, 8, 1> hash;
    SignatureVerifier signatureVerifier;

    OffchainWithdrawalGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& constants,
        const VariableT& accountsMerkleRoot,
        const VariableT& operatorBalancesRoot,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // User state
        balanceFBefore({
            make_variable(pb, FMT(prefix, ".beforeF.balance")),
            make_variable(pb, FMT(prefix, ".beforeF.tradingHistory"))
        }),
        balanceBefore({
            make_variable(pb, FMT(prefix, ".before.balance")),
            make_variable(pb, FMT(prefix, ".before.tradingHistory"))
        }),
        accountBefore({
            make_variable(pb, FMT(prefix, ".publicKeyX")),
            make_variable(pb, FMT(prefix, ".publicKeyY")),
            make_variable(pb, FMT(prefix, ".nonce")),
            make_variable(pb, FMT(prefix, ".before.balancesRoot"))
        }),
        // Operator state
        balanceF_O_before(make_variable(pb, FMT(prefix, ".balanceF_O_before"))),
        tradingHistoryRootF_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootF_O"))),

        // Inputs
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amountRequested(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amountRequested")),
        feeTokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".feeTokenID")),
        fee(pb, NUM_BITS_AMOUNT, FMT(prefix, ".fee")),
        label(pb, NUM_BITS_LABEL, FMT(prefix, ".label")),

        // Fee as float
        fFee(pb, constants, Float16Encoding, FMT(prefix, ".fFee")),
        requireAccuracyFee(pb, fFee.value(), fee.packed, Float16Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFee")),

        // Fee payment from the user to the operator
        feePayment(pb, NUM_BITS_AMOUNT, balanceFBefore.balance, balanceF_O_before, fFee.value(), FMT(prefix, ".feePayment")),

        // Calculate how much can be withdrawn
        amountToWithdraw(pb, amountRequested.packed, balanceBefore.balance, NUM_BITS_AMOUNT, FMT(prefix, ".min(amountRequested, balance)")),
        amountWithdrawn(pb, constants, Float28Encoding, FMT(prefix, ".amountWithdrawn")),
        requireAccuracyAmountWithdrawn(pb, amountWithdrawn.value(), amountToWithdraw.result(), Float28Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyAmountRequested")),

        // Calculate the new balance
        balance_after(pb, balanceBefore.balance, amountWithdrawn.value(), FMT(prefix, ".balance_after")),

        // Increase the nonce of the user by 1
        nonce_after(pb, accountBefore.nonce, constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_after")),

        // Update User
        updateBalanceF_A(pb, accountBefore.balancesRoot, feeTokenID.bits,
                         {balanceFBefore.balance, balanceFBefore.tradingHistory},
                         {feePayment.X, balanceFBefore.tradingHistory},
                         FMT(prefix, ".updateBalanceF_A")),
        updateBalance_A(pb, updateBalanceF_A.result(), tokenID.bits,
                        {balanceBefore.balance, balanceBefore.tradingHistory},
                        {balance_after.result(), balanceBefore.tradingHistory},
                        FMT(prefix, ".updateBalance_A")),
        updateAccount_A(pb, accountsMerkleRoot, accountID.bits,
                        {accountBefore.publicKeyX, accountBefore.publicKeyY, accountBefore.nonce, accountBefore.balancesRoot},
                        {accountBefore.publicKeyX, accountBefore.publicKeyY, nonce_after.result(), updateBalance_A.result()},
                        FMT(prefix, ".updateAccount_A")),

        // Update Operator
        updateBalanceF_O(pb, operatorBalancesRoot, feeTokenID.bits,
                         {balanceF_O_before, tradingHistoryRootF_O},
                         {feePayment.Y, tradingHistoryRootF_O},
                         FMT(prefix, ".updateBalanceF_O")),

        // Signature
        hash(pb, var_array({
            blockExchangeID,
            accountID.packed,
            tokenID.packed,
            amountRequested.packed,
            feeTokenID.packed,
            fee.packed,
            label.packed,
            accountBefore.nonce
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, jubjub::VariablePointT(accountBefore.publicKeyX, accountBefore.publicKeyY),
                          hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    void generate_r1cs_witness(const OffchainWithdrawal& withdrawal)
    {
        // User state
        pb.val(balanceFBefore.tradingHistory) = withdrawal.balanceUpdateF_A.before.tradingHistoryRoot;
        pb.val(balanceFBefore.balance) = withdrawal.balanceUpdateF_A.before.balance;
        pb.val(balanceBefore.tradingHistory) = withdrawal.balanceUpdateW_A.before.tradingHistoryRoot;
        pb.val(balanceBefore.balance) = withdrawal.balanceUpdateW_A.before.balance;
        pb.val(accountBefore.publicKeyX) = withdrawal.accountUpdate_A.before.publicKey.x;
        pb.val(accountBefore.publicKeyY) = withdrawal.accountUpdate_A.before.publicKey.y;
        pb.val(accountBefore.nonce) = withdrawal.accountUpdate_A.before.nonce;
        pb.val(accountBefore.balancesRoot) = withdrawal.accountUpdate_A.before.balancesRoot;
        // Operator state
        pb.val(balanceF_O_before) = withdrawal.balanceUpdateF_O.before.balance;
        pb.val(tradingHistoryRootF_O) = withdrawal.balanceUpdateF_O.before.tradingHistoryRoot;

        // Inputs
        accountID.bits.fill_with_bits_of_field_element(pb, withdrawal.accountUpdate_A.accountID);
        accountID.generate_r1cs_witness_from_bits();
        tokenID.bits.fill_with_bits_of_field_element(pb, withdrawal.balanceUpdateW_A.tokenID);
        tokenID.generate_r1cs_witness_from_bits();
        amountRequested.bits.fill_with_bits_of_field_element(pb, withdrawal.amountRequested);
        amountRequested.generate_r1cs_witness_from_bits();
        feeTokenID.bits.fill_with_bits_of_field_element(pb, withdrawal.balanceUpdateF_A.tokenID);
        feeTokenID.generate_r1cs_witness_from_bits();
        fee.bits.fill_with_bits_of_field_element(pb, withdrawal.fee);
        fee.generate_r1cs_witness_from_bits();
        label.bits.fill_with_bits_of_field_element(pb, withdrawal.label);
        label.generate_r1cs_witness_from_bits();

        // Fee as float
        fFee.generate_r1cs_witness(toFloat(withdrawal.fee, Float16Encoding));
        requireAccuracyFee.generate_r1cs_witness();

        // Fee payment from the user to the operator
        feePayment.generate_r1cs_witness();

        // Calculate how much can be withdrawn
        amountToWithdraw.generate_r1cs_witness();
        amountWithdrawn.generate_r1cs_witness(toFloat(pb.val(amountToWithdraw.result()), Float28Encoding));
        requireAccuracyAmountWithdrawn.generate_r1cs_witness();

        // Calculate the new balance
        balance_after.generate_r1cs_witness();

        // Increase the nonce of the user by 1
        nonce_after.generate_r1cs_witness();

        // Update User
        updateBalanceF_A.generate_r1cs_witness(withdrawal.balanceUpdateF_A.proof);
        updateBalance_A.generate_r1cs_witness(withdrawal.balanceUpdateW_A.proof);
        updateAccount_A.generate_r1cs_witness(withdrawal.accountUpdate_A.proof);

        // Update Operator
        updateBalanceF_O.generate_r1cs_witness(withdrawal.balanceUpdateF_O.proof);

        // Check signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(withdrawal.signature);
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        accountID.generate_r1cs_constraints(true);
        tokenID.generate_r1cs_constraints(true);
        amountRequested.generate_r1cs_constraints(true);
        feeTokenID.generate_r1cs_constraints(true);
        fee.generate_r1cs_constraints(true);
        label.generate_r1cs_constraints(true);

        // Fee as float
        fFee.generate_r1cs_constraints();
        requireAccuracyFee.generate_r1cs_constraints();

        // Fee payment from the user to the operator
        feePayment.generate_r1cs_constraints();

        // Calculate how much can be withdrawn
        amountToWithdraw.generate_r1cs_constraints();
        amountWithdrawn.generate_r1cs_constraints();
        requireAccuracyAmountWithdrawn.generate_r1cs_constraints();

        // Calculate the new balance
        balance_after.generate_r1cs_constraints();

        // Increase the nonce of the user by 1
        nonce_after.generate_r1cs_constraints();

        // Update User
        updateBalanceF_A.generate_r1cs_constraints();
        updateBalance_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();

        // Update Operator
        updateBalanceF_O.generate_r1cs_constraints();

        // Check signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_A.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceF_O.result();
    }

    const std::vector<VariableArrayT> getApprovedWithdrawalData() const
    {
        return {tokenID.bits,
                accountID.bits,
                amountWithdrawn.bits()};
    }

    const std::vector<VariableArrayT> getDataAvailabilityData() const
    {
        return {feeTokenID.bits,
                fFee.bits()};
    }
};

class OffchainWithdrawalCircuit : public GadgetT
{
public:

    PublicDataGadget publicData;
    Constants constants;
    jubjub::Params params;

    // State
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot_before;

    // Inputs
    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;
    libsnark::dual_variable_gadget<FieldT> operatorAccountID;

    // Operator account check
    RequireNotZeroGadget publicKeyX_notZero;

    // Withdrawals
    bool onchainDataAvailability;
    unsigned int numWithdrawals;
    std::vector<OffchainWithdrawalGadget> withdrawals;

    // Update Operator
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    // Labels
    std::vector<VariableT> labels;
    std::unique_ptr<LabelHasher> labelHasher;

    OffchainWithdrawalCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),
        constants(pb, FMT(prefix, ".constants")),

        // State
        publicKey(pb, FMT(prefix, ".publicKey")),
        nonce(make_variable(pb, 0, FMT(prefix, ".nonce"))),
        balancesRoot_before(make_variable(pb, 0, FMT(prefix, ".balancesRoot_before"))),

        // Inputs
        exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),
        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),

        // Operator account check
        publicKeyX_notZero(pb, publicKey.x, FMT(prefix, ".publicKeyX_notZero"))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numWithdrawals)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numWithdrawals = numWithdrawals;

        constants.generate_r1cs_constraints();

        // Inputs
        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);
        operatorAccountID.generate_r1cs_constraints(true);

        // Operator account check
        publicKeyX_notZero.generate_r1cs_constraints();

        // Withdrawals
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
            labels.push_back(withdrawals.back().label.packed);
        }

        // Update Operator
        updateAccount_O.reset(new UpdateAccountGadget(pb, withdrawals.back().getNewAccountsRoot(), operatorAccountID.bits,
            {publicKey.x, publicKey.y, nonce, balancesRoot_before},
            {publicKey.x, publicKey.y, nonce, withdrawals.back().getNewOperatorBalancesRoot()},
            FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Labels
        labelHasher.reset(new LabelHasher(pb, constants, labels, FMT(annotation_prefix, ".labelHash")));
        labelHasher->generate_r1cs_constraints();

        // Public data
        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        // Store the approved data for all withdrawals
        for (auto& withdrawal : withdrawals)
        {
            publicData.add(withdrawal.getApprovedWithdrawalData());
        }
        publicData.add(labelHasher->result()->bits);
        // Data availability
        if (onchainDataAvailability)
        {
            publicData.add(constants.padding_0000);
            publicData.add(operatorAccountID.bits);
            for (auto& withdrawal : withdrawals)
            {
                publicData.add(withdrawal.getDataAvailabilityData());
            }
        }
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    bool generateWitness(const OffchainWithdrawalBlock& block)
    {
        constants.generate_r1cs_witness();

        // State
        pb.val(publicKey.x) = block.accountUpdate_O.before.publicKey.x;
        pb.val(publicKey.y) = block.accountUpdate_O.before.publicKey.y;
        pb.val(nonce) = block.accountUpdate_O.before.nonce;
        pb.val(balancesRoot_before) = block.accountUpdate_O.before.balancesRoot;

        // Inputs
        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();
        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();
        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();

        // Operator account check
        publicKeyX_notZero.generate_r1cs_witness();

        // Withdrawals
        for(unsigned int i = 0; i < block.withdrawals.size(); i++)
        {
            withdrawals[i].generate_r1cs_witness(block.withdrawals[i]);
        }

        // Update Operator
        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        // Labels
        labelHasher->generate_r1cs_witness();

        // Public data
        publicData.generate_r1cs_witness();

        return true;
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numWithdrawals) << "/offchain withdrawal)" << std::endl;
    }
};

}

#endif
