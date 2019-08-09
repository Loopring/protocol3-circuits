#ifndef _ONCHAINWITHDRAWALCIRCUIT_H_
#define _ONCHAINWITHDRAWALCIRCUIT_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "../Utils/Utils.h"
#include "../Gadgets/AccountGadgets.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/merkle_tree.hpp"

using namespace ethsnarks;

namespace Loopring
{

class OnchainWithdrawalGadget : public GadgetT
{
public:

    // User state
    BalanceState balanceBefore;
    AccountState accountBefore;

    // Inputs
    libsnark::dual_variable_gadget<FieldT> accountID;
    libsnark::dual_variable_gadget<FieldT> tokenID;
    libsnark::dual_variable_gadget<FieldT> amountRequested;

    // Calculate how much can be withdrawn
    MinGadget amountToWithdrawMin;
    TernaryGadget amountToWithdraw;
    FloatGadget amountWithdrawn;
    RequireAccuracyGadget requireAccuracyAmountWithdrawn;

    // Shutdown mode
    TernaryGadget amountToSubtract;
    TernaryGadget tradingHistoryAfter;
    TernaryGadget publicKeyXAfter;
    TernaryGadget publicKeyYAfter;
    TernaryGadget nonceAfter;

    // Calculate the new balance
    UnsafeSubGadget balance_after;

    // Update User
    UpdateBalanceGadget updateBalance_A;
    UpdateAccountGadget updateAccount_A;

    OnchainWithdrawalGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& constants,
        const VariableT& accountsMerkleRoot,
        const VariableT& bShutdownMode,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // User state
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

        // Inputs
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amountRequested(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amountRequested")),

        // Calculate how much can be withdrawn
        amountToWithdrawMin(pb, amountRequested.packed, balanceBefore.balance, NUM_BITS_AMOUNT, FMT(prefix, ".min(amountRequested, balance)")),
        amountToWithdraw(pb, bShutdownMode, balanceBefore.balance, amountToWithdrawMin.result(), FMT(prefix, ".amountToWithdraw")),
        amountWithdrawn(pb, constants, Float28Encoding, FMT(prefix, ".amountWithdrawn")),
        requireAccuracyAmountWithdrawn(pb, amountWithdrawn.value(), amountToWithdraw.result(), Float28Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyAmountRequested")),

        // Shutdown mode
        amountToSubtract(pb, bShutdownMode, amountToWithdraw.result(), amountWithdrawn.value(), FMT(prefix, ".amountToSubtract")),
        tradingHistoryAfter(pb, bShutdownMode, constants.emptyTradeHistory, balanceBefore.tradingHistory, FMT(prefix, ".tradingHistoryAfter")),
        publicKeyXAfter(pb, bShutdownMode, constants.zero, accountBefore.publicKeyX, FMT(prefix, ".publicKeyXAfter")),
        publicKeyYAfter(pb, bShutdownMode, constants.zero, accountBefore.publicKeyY, FMT(prefix, ".publicKeyYAfter")),
        nonceAfter(pb, bShutdownMode, constants.zero, accountBefore.nonce, FMT(prefix, ".tradingHistoryAfter")),

        // Calculate the new balance
        balance_after(pb, balanceBefore.balance, amountToSubtract.result(), FMT(prefix, ".balance_after")),

        // Update User
        updateBalance_A(pb, accountBefore.balancesRoot, tokenID.bits,
                        {balanceBefore.balance, balanceBefore.tradingHistory},
                        {balance_after.result(), tradingHistoryAfter.result()},
                        FMT(prefix, ".updateBalance_A")),
        updateAccount_A(pb, accountsMerkleRoot, accountID.bits,
                        {accountBefore.publicKeyX, accountBefore.publicKeyY, accountBefore.nonce, accountBefore.balancesRoot},
                        {publicKeyXAfter.result(), publicKeyYAfter.result(), nonceAfter.result(), updateBalance_A.result()},
                        FMT(prefix, ".updateAccount_A"))
    {

    }

    void generate_r1cs_witness(const OnchainWithdrawal& withdrawal)
    {
        // User state
        pb.val(balanceBefore.tradingHistory) = withdrawal.balanceUpdate.before.tradingHistoryRoot;
        pb.val(balanceBefore.balance) = withdrawal.balanceUpdate.before.balance;
        pb.val(accountBefore.publicKeyX) = withdrawal.accountUpdate.before.publicKey.x;
        pb.val(accountBefore.publicKeyY) = withdrawal.accountUpdate.before.publicKey.y;
        pb.val(accountBefore.nonce) = withdrawal.accountUpdate.before.nonce;
        pb.val(accountBefore.balancesRoot) = withdrawal.accountUpdate.before.balancesRoot;

        // Inputs
        accountID.bits.fill_with_bits_of_field_element(pb, withdrawal.accountUpdate.accountID);
        accountID.generate_r1cs_witness_from_bits();
        tokenID.bits.fill_with_bits_of_field_element(pb, withdrawal.balanceUpdate.tokenID);
        tokenID.generate_r1cs_witness_from_bits();
        amountRequested.bits.fill_with_bits_of_field_element(pb, withdrawal.amountRequested);
        amountRequested.generate_r1cs_witness_from_bits();

        // Withdrawal calculations
        amountToWithdrawMin.generate_r1cs_witness();
        amountToWithdraw.generate_r1cs_witness();
        amountWithdrawn.generate_r1cs_witness(toFloat(pb.val(amountToWithdraw.result()), Float28Encoding));
        requireAccuracyAmountWithdrawn.generate_r1cs_witness();

        // Shutdown mode
        amountToSubtract.generate_r1cs_witness();
        tradingHistoryAfter.generate_r1cs_witness();
        publicKeyXAfter.generate_r1cs_witness();
        publicKeyYAfter.generate_r1cs_witness();
        nonceAfter.generate_r1cs_witness();

        // Calculate the new balance
        balance_after.generate_r1cs_witness();

        // Update User
        updateBalance_A.generate_r1cs_witness(withdrawal.balanceUpdate.proof);
        updateAccount_A.generate_r1cs_witness(withdrawal.accountUpdate.proof);
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        accountID.generate_r1cs_constraints(true);
        tokenID.generate_r1cs_constraints(true);
        amountRequested.generate_r1cs_constraints(true);

        // Withdrawal calculations
        amountToWithdrawMin.generate_r1cs_constraints();
        amountToWithdraw.generate_r1cs_constraints();
        amountWithdrawn.generate_r1cs_constraints();
        requireAccuracyAmountWithdrawn.generate_r1cs_constraints();

        // Shutdown mode
        amountToSubtract.generate_r1cs_constraints();
        tradingHistoryAfter.generate_r1cs_constraints();
        publicKeyXAfter.generate_r1cs_constraints();
        publicKeyYAfter.generate_r1cs_constraints();
        nonceAfter.generate_r1cs_constraints();

        // Calculate the new balance
        balance_after.generate_r1cs_constraints();

        // Update User
        updateBalance_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();
    }

    const std::vector<VariableArrayT> getOnchainData(const Constants& constants) const
    {
        return {constants.padding_0000, accountID.bits,
                tokenID.bits,
                amountRequested.bits};
    }

    const std::vector<VariableArrayT> getApprovedWithdrawalData() const
    {
        return {tokenID.bits,
                accountID.bits,
                amountWithdrawn.bits()};
    }

    const VariableT& getNewAccountsRoot() const
    {
        return updateAccount_A.result();
    }
};

class OnchainWithdrawalCircuit : public GadgetT
{
public:
    jubjub::Params params;

    bool onchainDataAvailability;
    unsigned int numWithdrawals;
    std::vector<OnchainWithdrawalGadget> withdrawals;

    PublicDataGadget publicData;

    Constants constants;

    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;

    VariableArrayT withdrawalBlockHashStart;
    libsnark::dual_variable_gadget<FieldT> startIndex;
    libsnark::dual_variable_gadget<FieldT> count;

    EqualGadget bShutdownMode;

    std::vector<sha256_many> hashers;

    OnchainWithdrawalCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),

        constants(pb, FMT(prefix, ".constants")),

        exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),

        withdrawalBlockHashStart(make_var_array(pb, 256, FMT(prefix, ".withdrawalBlockHashStart"))),
        startIndex(pb, 32, FMT(prefix, ".startIndex")),
        count(pb, 32, FMT(prefix, ".count")),

        bShutdownMode(pb, count.packed, constants.zero, FMT(prefix, ".bShutdownMode"))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numWithdrawals)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numWithdrawals = numWithdrawals;

        constants.generate_r1cs_constraints();

        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);

        startIndex.generate_r1cs_constraints(true);
        count.generate_r1cs_constraints(true);

        bShutdownMode.generate_r1cs_constraints();

        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        for (size_t j = 0; j < numWithdrawals; j++)
        {
            VariableT withdrawalAccountsRoot = (j == 0) ? merkleRootBefore.packed : withdrawals.back().getNewAccountsRoot();
            withdrawals.emplace_back(
                pb,
                params,
                constants,
                withdrawalAccountsRoot,
                bShutdownMode.result(),
                std::string("withdrawals_") + std::to_string(j)
            );
            withdrawals.back().generate_r1cs_constraints();

            VariableArrayT withdrawalBlockHash = (j == 0) ? withdrawalBlockHashStart : hashers.back().result().bits;

            // Hash data from withdrawal request
            std::vector<VariableArrayT> withdrawalRequestData = withdrawals.back().getOnchainData(constants);
            std::vector<VariableArrayT> hash;
            hash.push_back(reverse(withdrawalBlockHash));
            hash.insert(hash.end(), withdrawalRequestData.begin(), withdrawalRequestData.end());
            hashers.emplace_back(pb, flattenReverse(hash), std::string("hash_") + std::to_string(j));
            hashers.back().generate_r1cs_constraints();
        }

        // Add the ending hash
        publicData.add(reverse(withdrawalBlockHashStart));
        publicData.add(reverse(hashers.back().result().bits));
        publicData.add(startIndex.bits);
        publicData.add(count.bits);

        // Store the approved data for all withdrawals
        for (auto& withdrawal : withdrawals)
        {
            publicData.add(withdrawal.getApprovedWithdrawalData());
        }

        // Check the input hash
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, withdrawals.back().getNewAccountsRoot(), merkleRootAfter.packed, "newMerkleRoot");
    }

    bool generateWitness(const OnchainWithdrawalBlock& block)
    {
        constants.generate_r1cs_witness();

        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();

        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();

        // Store the starting hash
        for (unsigned int i = 0; i < 256; i++)
        {
            pb.val(withdrawalBlockHashStart[255 - i]) = block.startHash.test_bit(i);
        }
        // printBits("start hash input: 0x", depositBlockHashStart.get_bits(pb), true);
        startIndex.bits.fill_with_bits_of_field_element(pb, block.startIndex);
        startIndex.generate_r1cs_witness_from_bits();
        count.bits.fill_with_bits_of_field_element(pb, block.count);
        count.generate_r1cs_witness_from_bits();

        bShutdownMode.generate_r1cs_witness();

        // All withdrawals
        for(unsigned int i = 0; i < block.withdrawals.size(); i++)
        {
            withdrawals[i].generate_r1cs_witness(block.withdrawals[i]);
        }

        // All hashes
        for (auto& hasher : hashers)
        {
            hasher.generate_r1cs_witness();
        }
        printBits("WithdrawBlockHash: 0x", hashers.back().result().bits.get_bits(pb));

        // Public data
        publicData.generate_r1cs_witness();

        return true;
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numWithdrawals) << "/onchain withdrawal)" << std::endl;
    }
};

}

#endif
