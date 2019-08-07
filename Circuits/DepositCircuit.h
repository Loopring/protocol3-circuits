#ifndef _DEPOSITCIRCUIT_H_
#define _DEPOSITCIRCUIT_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "../ThirdParty/BigInt.hpp"
#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/sha256_many.hpp"

using namespace ethsnarks;

namespace Loopring
{

class DepositGadget : public GadgetT
{
public:
    const Constants& constants;

    VariableArrayT accountID;
    VariableArrayT tokenID;

    libsnark::dual_variable_gadget<FieldT> amount;
    libsnark::dual_variable_gadget<FieldT> publicKeyX;
    libsnark::dual_variable_gadget<FieldT> publicKeyY;

    BalanceState balanceBefore;
    AccountState accountBefore;
    UnsafeAddGadget uncappedBalanceAfter;
    MinGadget cappedBalanceAfter;
    BalanceState balanceAfter;
    UpdateBalanceGadget updateBalance;
    AccountState accountAfter;
    UpdateAccountGadget updateAccount;

    DepositGadget(
        ProtoboardT& pb,
        const Constants& _constants,
        const VariableT& root,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        constants(_constants),

        accountID(make_var_array(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID"))),
        tokenID(make_var_array(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID"))),

        amount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amount")),
        publicKeyX(pb, 256, FMT(prefix, ".publicKeyX")),
        publicKeyY(pb, 256, FMT(prefix, ".publicKeyY")),

        // Balance
        balanceBefore({
            make_variable(pb, FMT(prefix, ".before.balance")),
            make_variable(pb, FMT(prefix, ".tradingHistoryRoot"))
        }),
        uncappedBalanceAfter(pb, balanceBefore.balance, amount.packed, FMT(prefix, ".uncappedBalanceAfter")),
        cappedBalanceAfter(pb, uncappedBalanceAfter.result(), constants.maxAmount, NUM_BITS_AMOUNT + 1, FMT(prefix, ".cappedBalanceAfter")),
        balanceAfter({
            cappedBalanceAfter.result(),
            balanceBefore.tradingHistory
        }),
        // Account
        accountBefore({
            make_variable(pb, FMT(prefix, ".publicKeyX_before")),
            make_variable(pb, FMT(prefix, ".publicKeyY_before")),
            make_variable(pb, FMT(prefix, ".nonce")),
            make_variable(pb, FMT(prefix, ".balancesRoot_before"))
        }),
        // Update balance
        updateBalance(pb, accountBefore.balancesRoot, tokenID, balanceBefore, balanceAfter, FMT(prefix, ".updateBalance")),
        accountAfter({
            publicKeyX.packed,
            publicKeyY.packed,
            accountBefore.nonce,
            updateBalance.result()
        }),
        // Update account
        updateAccount(pb, root, accountID, accountBefore, accountAfter, FMT(prefix, ".updateAccount"))
    {

    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount.result();
    }

    const std::vector<VariableArrayT> getOnchainData() const
    {
        return {constants.padding_0000, accountID,
                publicKeyX.bits, publicKeyY.bits,
                tokenID,
                amount.bits};
    }

    void generate_r1cs_witness(const Deposit& deposit)
    {
        accountID.fill_with_bits_of_field_element(pb, deposit.accountUpdate.accountID);
        tokenID.fill_with_bits_of_field_element(pb, deposit.balanceUpdate.tokenID);

        amount.bits.fill_with_bits_of_field_element(pb, deposit.amount);
        amount.generate_r1cs_witness_from_bits();
        publicKeyX.bits.fill_with_bits_of_field_element(pb, deposit.accountUpdate.after.publicKey.x);
        publicKeyX.generate_r1cs_witness_from_bits();
        publicKeyY.bits.fill_with_bits_of_field_element(pb, deposit.accountUpdate.after.publicKey.y);
        publicKeyY.generate_r1cs_witness_from_bits();

        pb.val(balanceBefore.balance) = deposit.balanceUpdate.before.balance;
        pb.val(balanceBefore.tradingHistory) = deposit.balanceUpdate.before.tradingHistoryRoot;

        uncappedBalanceAfter.generate_r1cs_witness();
        cappedBalanceAfter.generate_r1cs_witness();

        pb.val(accountBefore.publicKeyX) = deposit.accountUpdate.before.publicKey.x;
        pb.val(accountBefore.publicKeyY) = deposit.accountUpdate.before.publicKey.y;
        pb.val(accountBefore.nonce) = deposit.accountUpdate.before.nonce;
        pb.val(accountBefore.balancesRoot) = deposit.accountUpdate.before.balancesRoot;

        updateBalance.generate_r1cs_witness(deposit.balanceUpdate.proof);
        updateAccount.generate_r1cs_witness(deposit.accountUpdate.proof);
    }

    void generate_r1cs_constraints()
    {
        amount.generate_r1cs_constraints(true);
        publicKeyX.generate_r1cs_constraints(true);
        publicKeyY.generate_r1cs_constraints(true);

        uncappedBalanceAfter.generate_r1cs_constraints();
        cappedBalanceAfter.generate_r1cs_constraints();

        updateBalance.generate_r1cs_constraints();
        updateAccount.generate_r1cs_constraints();
    }
};

class DepositCircuit : public GadgetT
{
public:

    unsigned int numAccounts;
    std::vector<DepositGadget> deposits;

    PublicDataGadget publicData;

    Constants constants;

    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;

    VariableArrayT depositBlockHashStart;
    libsnark::dual_variable_gadget<FieldT> startIndex;
    libsnark::dual_variable_gadget<FieldT> count;

    std::vector<sha256_many> hashers;

    DepositCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),

        constants(pb, FMT(prefix, ".constants")),

        exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),

        depositBlockHashStart(make_var_array(pb, 256, FMT(prefix, ".depositBlockHashStart"))),
        startIndex(pb, 32, FMT(prefix, ".startIndex")),
        count(pb, 32, FMT(prefix, ".count"))
    {

    }

    void generate_r1cs_constraints(int numAccounts)
    {
        this->numAccounts = numAccounts;

        constants.generate_r1cs_constraints();

        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);

        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        publicData.add(reverse(depositBlockHashStart));
        for (size_t j = 0; j < numAccounts; j++)
        {
            VariableT depositAccountsRoot = (j == 0) ? merkleRootBefore.packed : deposits.back().getNewAccountsRoot();
            deposits.emplace_back(
                pb,
                constants,
                depositAccountsRoot,
                std::string("deposit_") + std::to_string(j)
            );
            deposits.back().generate_r1cs_constraints();

            VariableArrayT depositBlockHash = (j == 0) ? depositBlockHashStart : hashers.back().result().bits;

            // Hash data from deposit
            std::vector<VariableArrayT> depositData = deposits.back().getOnchainData();
            std::vector<VariableArrayT> hashBits;
            hashBits.push_back(reverse(depositBlockHash));
            hashBits.insert(hashBits.end(), depositData.begin(), depositData.end());
            hashers.emplace_back(pb, flattenReverse(hashBits), std::string("hash_") + std::to_string(j));
            hashers.back().generate_r1cs_constraints();
        }

        // Add the block hash
        publicData.add(reverse(hashers.back().result().bits));
        publicData.add(startIndex.bits);
        publicData.add(count.bits);

        // Check the input hash
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, deposits.back().getNewAccountsRoot(), merkleRootAfter.packed, "newMerkleRoot");
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numAccounts) << "/deposit)" << std::endl;
    }

    bool generateWitness(const DepositBlock& block)
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
            pb.val(depositBlockHashStart[255 - i]) = block.startHash.test_bit(i);
        }
        // printBits("start hash input: 0x", depositBlockHashStart.get_bits(pb), true);

        startIndex.bits.fill_with_bits_of_field_element(pb, block.startIndex);
        startIndex.generate_r1cs_witness_from_bits();
        count.bits.fill_with_bits_of_field_element(pb, block.count);
        count.generate_r1cs_witness_from_bits();

        for(unsigned int i = 0; i < block.deposits.size(); i++)
        {
            deposits[i].generate_r1cs_witness(block.deposits[i]);
        }

        for (auto& hasher : hashers)
        {
            hasher.generate_r1cs_witness();
        }
        printBits("DepositBlockHash: 0x", hashers.back().result().bits.get_bits(pb));

        publicData.generate_r1cs_witness();

        return true;
    }
};

}

#endif
